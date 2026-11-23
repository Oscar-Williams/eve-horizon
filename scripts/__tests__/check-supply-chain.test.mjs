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

  it('follows a version passed through an ARG or ENV to its default, in the stage that reads it', () => {
    const offences = checkDockerfile(
      [
        'ARG GLOBAL_VERSION=1.0.0',
        'FROM scratch',
        'ARG GOOD_VERSION=1.2.3',
        'ARG LOOSE_VERSION=^2.0.0',
        'ARG BARE_VERSION',
        'ENV TOOL_VERSION=4.5.6',
        'RUN npm install -g "one@${GOOD_VERSION}" two@$LOOSE_VERSION three@${BARE_VERSION} four@${UNDEFINED} five@${TOOL_VERSION}',
        'RUN pip install "six==${GOOD_VERSION}" seven==${LOOSE_VERSION}',
        'RUN npm i eight@${GLOBAL_VERSION}',
        'ARG GLOBAL_VERSION',
        'RUN npm i nine@${GLOBAL_VERSION}',
        'FROM scratch AS later',
        'RUN npm i ten@${GOOD_VERSION}',
      ].join('\n'),
    );
    assert.deepEqual(
      offences.map(({ line, message }) => `${line} ${message}`),
      [
        '7 npm package two@$LOOSE_VERSION (two@^2.0.0) has no exact version',
        '7 npm package three@${BARE_VERSION} (no default) has no exact version',
        '7 npm package four@${UNDEFINED} (no default) has no exact version',
        '8 pip package seven==${LOOSE_VERSION} (seven==^2.0.0) has no exact version',
        '9 npm package eight@${GLOBAL_VERSION} (no default) has no exact version',
        '13 npm package ten@${GOOD_VERSION} (no default) has no exact version',
      ],
    );
  });

  it('rejects npx, pnpm add, yarn add and pip install without an exact version', () => {
    const offences = checkDockerfile(
      [
        'FROM scratch',
        'RUN npx --yes cc-mirror quick && npx -y tool@1.2.3 run && npx -p helper@^1 -p other@2.0.0 cmd arg',
        'RUN pnpm add -g pkg-a && pnpm --filter app add pkg-b@1.0.0 && yarn add pkg-c@~1.0.0 && yarn global add pkg-d@2.0.0',
        'RUN pip3 install --break-system-packages uv \\',
        '    && python3 -m pip install --no-cache-dir "req[extra]==1.2.3" "loose>=1.0" -r requirements.txt . \\',
        '    && uv pip install pkg-e==1.0.* pkg-f===2.0.0 --index-url https://pypi.example/simple',
        'RUN pnpm install --frozen-lockfile && npm ci && pip install -e ./local',
      ].join('\n'),
    );
    assert.deepEqual(
      offences.map(({ line, message }) => `${line} ${message}`),
      [
        '2 npx package cc-mirror has no exact version',
        '2 npx package helper@^1 has no exact version',
        '3 pnpm package pkg-a has no exact version',
        '3 yarn package pkg-c@~1.0.0 has no exact version',
        '4 pip package uv has no exact version',
        '5 pip package loose>=1.0 has no exact version',
        '6 pip package pkg-e==1.0.* has no exact version',
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
    assert.deepEqual(lines(offences), [6, 9, 11, 12, 13, 13, 22]);
    assert.equal(offences[0].message, 'run: interpolates ${{ github.ref_name }}; pass it through env:');
  });

  it('rejects env and matrix expressions inside run:, which env: passes safely', () => {
    const offences = checkWorkflow(
      [
        'jobs:',
        '  build:',
        '    strategy:',
        '      matrix:',
        '        name: [a, b]',
        '    name: Build ${{ matrix.name }}',
        '    steps:',
        '      - run: echo ${{ env.TAG }}',
        '      - name: each',
        '        run: |',
        '          echo "${{ matrix.name }}" "$NAME" "${{ vars.SAFE }}"',
        '        env:',
        '          NAME: ${{ matrix.name }}',
        '          TAG: ${{ env.TAG }}',
      ].join('\n'),
    );
    assert.deepEqual(
      offences.map(({ line, message }) => `${line} ${message}`),
      [
        '8 run: interpolates ${{ env.TAG }}; pass it through env:',
        '11 run: interpolates ${{ matrix.name }}; pass it through env:',
      ],
    );
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

describe('the worker image', () => {
  // The entrypoint installs nothing at start, so a variant hidden as built
  // would leave its harness silently missing (or, for zai, holding the
  // placeholder key that overrides the runtime one).
  it('fails its build when a cc-mirror variant cannot be built', async () => {
    const { readFileSync } = await import('node:fs');
    // As Docker reads it: comment lines dropped (also inside a continued
    // instruction), then continuation lines joined.
    const run = readFileSync(join(ROOT, 'apps', 'worker', 'Dockerfile'), 'utf8')
      .split(/\r?\n/)
      .filter((line) => !/^\s*#/.test(line))
      .join('\n')
      .replace(/\\\n/g, ' ')
      .split('\n')
      .find((line) => /^RUN\b.*cc-mirror quick/.test(line));
    assert.ok(run, 'the worker Dockerfile builds the cc-mirror variants');
    assert.match(run, /^RUN set -eu;/, 'the variant step stops at the first failure');
    assert.doesNotMatch(run, /\|\||2>\/dev\/null/, 'no failure in the variant step is hidden');
    assert.match(run, /--name mclaude\b/);
    assert.match(run, /--name zai\b/);
  });
});

describe('the harness CLI lock', () => {
  it('is committed, so npm ci in the image builds installs exactly what was reviewed', async () => {
    const { execFileSync } = await import('node:child_process');
    const tracked = execFileSync('git', ['ls-files', 'docker/harness-clis/package-lock.json'], { encoding: 'utf8', cwd: ROOT }).trim();
    assert.equal(tracked, 'docker/harness-clis/package-lock.json');
  });
});

describe('publishing workflows', () => {
  const workflowsDir = join(ROOT, '.github', 'workflows');

  /** Each step of the workflow's first job, as its lines joined. */
  function firstJobSteps(text) {
    const lines = text.split(/\r?\n/);
    const jobs = lines.findIndex((line) => /^jobs:\s*$/.test(line));
    assert.notEqual(jobs, -1, 'no jobs: block');
    const job = lines.findIndex((line, i) => i > jobs && /^ {2}[\w-]+:\s*$/.test(line));
    const end = lines.findIndex((line, i) => i > job && /^ {2}[\w-]+:\s*$/.test(line));
    const body = lines.slice(job + 1, end === -1 ? lines.length : end);
    const stepsAt = body.findIndex((line) => /^ {4}steps:\s*$/.test(line));
    const steps = [];
    for (const line of body.slice(stepsAt + 1)) {
      if (/^ {6}- /.test(line)) steps.push(line.trim());
      else if (steps.length > 0 && /^ {8}/.test(line)) steps[steps.length - 1] += `\n${line.trim()}`;
      else if (line.trim() !== '' && !/^ {6,}/.test(line)) break;
    }
    return steps;
  }

  it('run the supply-chain gate and its tests first, so a tag or hotfix release is gated too', async () => {
    const { readdirSync, readFileSync } = await import('node:fs');
    const publishing = readdirSync(workflowsDir)
      .filter((file) => /\.ya?ml$/.test(file))
      .filter((file) => /^\s*environment:\s*release\s*$/m.test(readFileSync(join(workflowsDir, file), 'utf8')))
      .sort();
    assert.deepEqual(publishing, ['publish-chat.yml', 'publish-cli.yml', 'publish-images.yml', 'publish-sdk.yml', 'toolchain-images.yml']);

    for (const file of publishing) {
      const steps = firstJobSteps(readFileSync(join(workflowsDir, file), 'utf8'));
      assert.match(steps[0] ?? '', /uses: actions\/checkout@/, `${file}: the first job starts with the checkout`);
      assert.match(steps[1] ?? '', /\nrun: node scripts\/check-supply-chain\.mjs$/, `${file}: then runs the gate`);
      assert.match(
        steps[2] ?? '',
        /\nrun: node --test scripts\/__tests__\/check-supply-chain\.test\.mjs$/,
        `${file}: then runs its tests`,
      );
      assert.doesNotMatch(`${steps[1]}\n${steps[2]}`, /\bif:/, `${file}: the gate runs on every trigger`);
    }
  });

  /** A workflow's jobs, by name, each as its lines joined. */
  function jobsOf(text) {
    const lines = text.split(/\r?\n/);
    const jobs = lines.findIndex((line) => /^jobs:\s*$/.test(line));
    const starts = lines.flatMap((line, i) => (i > jobs && /^ {2}[\w-]+:\s*$/.test(line) ? [i] : []));
    return Object.fromEntries(
      starts.map((start, n) => [lines[start].trim().slice(0, -1), lines.slice(start, starts[n + 1] ?? lines.length).join('\n')]),
    );
  }

  /** A job's steps, each as its lines joined. */
  function stepsOf(job) {
    const steps = [];
    for (const line of job.split('\n')) {
      if (/^ {6}- /.test(line)) steps.push(line);
      else if (steps.length > 0 && /^ {8}/.test(line)) steps[steps.length - 1] += `\n${line}`;
    }
    return steps;
  }

  /** The tarballs each npm workflow publishes, in order (pnpm names a scoped package's tarball scope-name-version). */
  const NPM_PACKAGES = {
    'publish-chat.yml': ['eve-horizon-chat', 'eve-horizon-chat-react'],
    'publish-cli.yml': ['eve-horizon-cli'],
    'publish-sdk.yml': ['eve-horizon-auth', 'eve-horizon-auth-react'],
  };

  it('publish to npm by trusted publishing, from a job that only publishes what an earlier job packed', async () => {
    const { readFileSync } = await import('node:fs');
    for (const [file, packages] of Object.entries(NPM_PACKAGES)) {
      const text = readFileSync(join(workflowsDir, file), 'utf8');
      assert.doesNotMatch(text, /NPM_TOKEN|NODE_AUTH_TOKEN/, `${file}: no npm token; npm trusts the workflow instead`);
      assert.doesNotMatch(text, /^\s*cache:|actions\/cache@|registry-url:/m, `${file}: no cache, and no .npmrc token placeholder`);

      const jobs = jobsOf(text);
      const release = Object.keys(jobs).filter((name) => /^ {4}environment:\s*release\s*$/m.test(jobs[name]));
      assert.equal(release.length, 1, `${file}: one job runs in the release environment`);
      const job = jobs[release[0]];
      // One grant of the identity token in the whole file, in the release
      // job, and every job sets its own permissions, so nothing inherits it.
      assert.equal([...text.matchAll(/^\s*id-token:/gm)].length, 1, `${file}: one grant of the identity token`);
      assert.match(job, /^ {6}id-token: write(?:\s+#.*)?$/m, `${file}: and it is the release job's`);
      for (const [name, body] of Object.entries(jobs)) {
        assert.match(body, /^ {4}permissions:\s*$/m, `${file}: ${name} sets its own permissions`);
      }
      // Any code that runs where the identity token can be requested could publish.
      assert.doesNotMatch(
        job,
        /actions\/checkout@|\bpnpm\b|\bnpm (?:ci|run|exec|version)\b|\bnpx\b|npm install (?!--global npm@)/,
        `${file}: the release job runs none of the repository's code or dependencies`,
      );

      const steps = stepsOf(job);
      const find = (pattern, what) => {
        const i = steps.findIndex((step) => pattern.test(step));
        assert.notEqual(i, -1, `${file}: the release job ${what}`);
        return i;
      };
      const node = find(/uses: actions\/setup-node@/, 'sets up Node');
      // npm takes an identity token from 11.5.1; Node 22 ships npm 10.
      const npm = find(/^ {8}run: npm install --global npm@\d+\.\d+\.\d+$/m, 'installs an exact npm version');
      const download = find(/uses: actions\/download-artifact@/, 'downloads the packed packages');
      assert.match(steps[download], /^ {10}name: npm-packages$/m, `${file}: the artifact the pack job uploads`);
      assert.match(steps[download], /^ {10}path: \$\{\{ runner\.temp \}\}\/packages$/m, `${file}: into the folder it publishes from`);
      const publishes = steps.flatMap((step, i) => (/\bnpm publish\b/.test(step) ? [i] : []));
      const published = publishes.map((i) => {
        const step = steps[i];
        const tarball = step.match(/^ {10}tarball=\$\(echo "\$RUNNER_TEMP"\/packages\/([\w-]+)-\[0-9\]\*\.tgz\)$/m)?.[1];
        assert.match(step, /^ {12}npm publish "\$tarball" --access public --ignore-scripts$/m, `${file}: publishes the tarball with scripts off`);
        // A re-run after a partly failed release skips what is already on npm.
        assert.match(step, /if \[ "\$\(npm view "@eve-horizon\/[\w-]+@\$version" version\)" = "\$version" \]; then/, `${file}: skips a published version`);
        assert.doesNotMatch(step, /^ {8}if:/m, `${file}: the publish always runs`);
        return tarball;
      });
      assert.deepEqual(published, packages, `${file}: publishes each packed tarball by name`);
      assert.ok(node < npm && npm < publishes[0] && download < publishes[0], `${file}: Node, then npm, then the publishes`);
      for (const i of [node, npm, download]) {
        assert.doesNotMatch(steps[i], /^ {8}if:/m, `${file}: every step the publish needs always runs`);
      }
      const [major, minor, patch] = steps[npm].match(/npm@(\d+)\.(\d+)\.(\d+)/).slice(1).map(Number);
      assert.ok(
        major > 11 || (major === 11 && (minor > 5 || (minor === 5 && patch >= 1))),
        `${file}: npm ${major}.${minor}.${patch} cannot publish with an identity token`,
      );

      // The release job takes the packages from a job that packs them, which
      // itself waits for the ancestry check (and the supply-chain gate in it).
      const packer = job.match(/^ {4}needs: ([\w-]+)\s*$/m)?.[1];
      assert.ok(packer && jobs[packer], `${file}: the release job needs the job that packs`);
      assert.match(jobs[packer], /^ {4}needs: ancestry\s*$/m, `${file}: ${packer} waits for the ancestry check`);
      assert.doesNotMatch(jobs[packer], /^ {4}environment:/m, `${file}: ${packer} runs outside the release environment`);
      const packSteps = stepsOf(jobs[packer]).filter((step) => /pnpm pack\b/.test(step));
      assert.equal(packSteps.length, packages.length, `${file}: ${packer} packs each package`);
      for (const step of packSteps) {
        assert.match(step, /^ {8}working-directory: packages\/[\w-]+$/m, `${file}: each pack runs in its package`);
        assert.match(step, /^ {8}run: pnpm pack --pack-destination "\$RUNNER_TEMP\/packages"$/m, `${file}: into the upload folder`);
      }
      const upload = stepsOf(jobs[packer]).find((step) => /uses: actions\/upload-artifact@/.test(step));
      assert.ok(upload, `${file}: ${packer} uploads what it packed`);
      assert.match(upload, /^ {10}name: npm-packages$/m, `${file}: as npm-packages`);
      assert.match(upload, /^ {10}path: \$\{\{ runner\.temp \}\}\/packages\/\*\.tgz$/m, `${file}: every tarball it packed`);
      assert.match(upload, /^ {10}if-no-files-found: error$/m, `${file}: failing when there are none`);
      // An approval can come days after the tag.
      const days = Number(upload.match(/^ {10}retention-days: (\d+)$/m)?.[1]);
      assert.ok(days >= 7, `${file}: the tarballs are kept at least 7 days for a late approval`);
    }
  });
});
