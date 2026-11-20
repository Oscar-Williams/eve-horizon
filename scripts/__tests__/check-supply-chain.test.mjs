import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { checkDockerfile, checkWorkflow, findOffences, formatOffence } from '../check-supply-chain.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIGEST = `sha256:${'a'.repeat(64)}`;
const SHA = 'b'.repeat(40);

const lines = (offences) => offences.map(({ line }) => line);
const messages = (offences) => offences.map(({ message }) => message);

describe('Dockerfile packages', () => {
  it('rejects @latest anywhere, and ARG package defaults without an exact version', () => {
    const offences = checkDockerfile(
      [
        'FROM scratch',
        'ARG CLI_PACKAGE=example-cli@latest',
        'ARG TOOL_PACKAGE=@example/tool',
        'ARG KIT_PACKAGE=@example/kit@^2.1.0',
        'ARG GOOD_PACKAGE=@example/good@1.2.3',
        'RUN corepack prepare pnpm@latest --activate',
        '# RUN npm install -g ignored@latest',
      ].join('\n'),
    );
    assert.deepEqual(lines(offences), [2, 3, 4, 6]);
    assert.match(offences[0].message, /example-cli@latest floats on @latest/);
    assert.match(offences[1].message, /ARG TOOL_PACKAGE=@example\/tool is not an exact package version/);
    assert.match(offences[3].message, /pnpm@latest floats on @latest/);
  });

  it('rejects npm install arguments without an exact version, on their own line', () => {
    const offences = checkDockerfile(
      [
        'FROM scratch',
        'RUN set -eu; \\',
        '    npm install -g --no-save \\',
        '      "first@1.0.0" \\',
        '      second \\',
        '      @scope/third@2 \\',
        '      "$FROM_AN_ARG" \\',
        '      ./local-folder \\',
        '    && npm i fourth@latest',
        'RUN npm install --prefix /opt/tools fifth@3.4.5-rc.1 && npm ci --ignore-scripts',
      ].join('\n'),
    );
    assert.deepEqual(
      offences.map(({ line, message }) => `${line} ${message}`),
      [
        '5 npm package second has no exact version',
        '6 npm package @scope/third@2 has no exact version',
        '9 fourth@latest floats on @latest',
      ],
    );
  });
});

describe('Dockerfile base images', () => {
  it('rejects FROM and COPY --from images without a digest', () => {
    const offences = checkDockerfile(
      [
        'FROM node:22-slim AS build',
        `FROM --platform=linux/amd64 node:22-slim@${DIGEST} AS runtime`,
        'FROM build AS again',
        'FROM scratch',
        'COPY --from=build /a /a',
        'COPY --from=1 /b /b',
        'COPY --from=registry.example/tools:1.0 /c /c',
        `COPY --from=registry.example/tools@${DIGEST} /d /d`,
      ].join('\n'),
    );
    assert.deepEqual(messages(offences), [
      'FROM node:22-slim is not pinned by @sha256 digest',
      'COPY --from=registry.example/tools:1.0 is not pinned by @sha256 digest',
    ]);
    assert.deepEqual(lines(offences), [1, 7]);
  });

  it('allows FROM ${ARG} only when the global ARG default is pinned by digest', () => {
    const pinned = checkDockerfile([`ARG BASE=node:22-slim@${DIGEST}`, 'FROM ${BASE} AS base', 'FROM $BASE'].join('\n'));
    assert.deepEqual(pinned, []);

    const unpinned = checkDockerfile(
      ['ARG BASE=node:22-slim', 'FROM ${BASE} AS base', 'FROM ${MISSING}', 'ARG LATE=x@' + DIGEST, 'FROM ${LATE}'].join('\n'),
    );
    assert.deepEqual(messages(unpinned), [
      'FROM ${BASE} (default node:22-slim) is not pinned by @sha256 digest',
      'FROM ${MISSING} (default undefined) is not pinned by @sha256 digest',
      // An ARG declared after the first FROM is not in scope for FROM lines.
      'FROM ${LATE} (default undefined) is not pinned by @sha256 digest',
    ]);
  });
});

describe('workflow actions', () => {
  it('requires a commit SHA, allowing local actions and docker images by digest', () => {
    const offences = checkWorkflow(
      [
        'jobs:',
        '  build:',
        '    steps:',
        '      - uses: actions/checkout@v4',
        `      - uses: actions/checkout@${SHA} # v4.4.0`,
        `      - uses: 'example/action/sub@${SHA}'`,
        '      - uses: ./.github/actions/local',
        '      - uses: docker://alpine:3',
        `      - uses: docker://alpine@${DIGEST}`,
        '      - name: short sha',
        '        uses: example/action@abc1234',
        '  reuse:',
        '    uses: example/repo/.github/workflows/w.yml@main',
      ].join('\n'),
    );
    assert.deepEqual(lines(offences), [4, 8, 11, 13]);
    assert.equal(offences[0].message, 'uses: actions/checkout@v4 is not pinned to a commit SHA');
  });
});

describe('workflow run blocks', () => {
  it('rejects github, inputs, step output and job output expressions inside run:', () => {
    const offences = checkWorkflow(
      [
        'on: push',
        'concurrency: ${{ github.ref }}',
        'jobs:',
        '  publish:',
        '    steps:',
        '      - run: echo ${{ github.ref_name }}',
        '      - name: block',
        '        run: |',
        '          echo "${{ matrix.name }}"',
        '',
        '          echo "${{ needs.version.outputs.value }}"',
        '          # a shell comment is interpolated too: ${{ inputs.tag }}',
        '          echo ${{ steps.version.outputs.VERSION }} ${{ env.SAFE }} ${{ secrets.TOKEN }}',
        '        env:',
        '          VERSION: ${{ steps.version.outputs.VERSION }}',
        '          REF: ${{ github.ref_name }}',
        '      - uses: example/action@' + SHA,
        '        with:',
        '          version: ${{ needs.version.outputs.value }}',
        '      - run: >-',
        '          echo',
        '          ${{ github.event.head_commit.message }}',
      ].join('\n'),
    );
    assert.deepEqual(lines(offences), [6, 11, 12, 13, 22]);
    assert.equal(offences[0].message, 'run: interpolates ${{ github.ref_name }}; pass it through env:');
  });
});

describe('repository scan', () => {
  it('checks Dockerfiles and workflows, skipping node_modules and tests/manual', () => {
    const root = mkdtempSync(join(tmpdir(), 'supply-chain-'));
    try {
      const write = (path, text) => {
        mkdirSync(dirname(join(root, path)), { recursive: true });
        writeFileSync(join(root, path), text);
      };
      write('apps/one/Dockerfile', 'FROM node:22\n');
      write('docker/two/build.Dockerfile', `FROM node@${DIGEST}\n`);
      write('docker/three/Dockerfile.cli', 'FROM alpine:3\n');
      write('.github/workflows/ci.yml', 'steps:\n  - uses: actions/checkout@v4\n');
      write('.github/actions/local/action.yml', 'runs:\n  steps:\n    - run: echo ${{ inputs.x }}\n');
      write('node_modules/pkg/Dockerfile', 'FROM node:22\n');
      write('tests/manual/fixture/Dockerfile', 'FROM node:22\n');
      write('docs/Dockerfile-notes.md', 'FROM node:22\n');

      assert.deepEqual(findOffences(root).map(formatOffence), [
        '.github/actions/local/action.yml:3: run: interpolates ${{ inputs.x }}; pass it through env:',
        '.github/workflows/ci.yml:2: uses: actions/checkout@v4 is not pinned to a commit SHA',
        'apps/one/Dockerfile:1: FROM node:22 is not pinned by @sha256 digest',
        'docker/three/Dockerfile.cli:1: FROM alpine:3 is not pinned by @sha256 digest',
      ]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('finds no offences in this repository', () => {
    const offences = findOffences(ROOT);
    assert.equal(offences.length, 0, `supply-chain offences:\n${offences.map(formatOffence).join('\n')}`);
  });
});
