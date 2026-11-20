require 'yaml'

# Every publisher first proves the tagged commit is on origin/main or an
# origin/hotfix/* branch, and publishes only through the `release` environment.
def check_release_gate(file, jobs, publisher)
  ancestry = jobs.fetch('ancestry') { abort "#{file}: missing ancestry job" }
  abort "#{file}: ancestry check missing" unless ancestry['steps'].to_s.include?('ancestry.sh')
  checkout = ancestry['steps'].find { |step| step['uses'].to_s.start_with?('actions/checkout@') }
  abort "#{file}: ancestry needs full history" unless checkout && checkout.dig('with', 'fetch-depth') == 0
  first = jobs.reject { |name, _| name == 'ancestry' }.reject { |_, job| job['needs'] }.keys
  abort "#{file}: #{first.join(', ')} may start before the ancestry check" unless first.empty?
  abort "#{file}: publisher outside the release environment" unless jobs[publisher]['environment'] == 'release'
end

files = {
  'service' => '.github/workflows/publish-images.yml',
  'toolchain' => '.github/workflows/toolchain-images.yml'
}
files.each do |kind, file|
  document = YAML.load_file(file)
  jobs = document.fetch('jobs')
  abort "#{file}: missing build/gate/prepublish/publish" unless %w[build native-gate prepublish publish].all? { |name| jobs.key?(name) }
  abort "#{file}: native gate may start before all builds" unless jobs['native-gate']['needs'].include?('build')
  abort "#{file}: prepublish may start before gate" unless jobs['prepublish']['needs'].include?('native-gate')
  abort "#{file}: publishers may start before global prepublish" unless jobs['publish']['needs'].include?('prepublish')
  abort "#{file}: dispatch can publish" unless jobs['publish']['if'].include?("github.event_name == 'push'") && jobs['prepublish']['if'].include?("github.event_name == 'push'")
  jobs.each do |name, job|
    permissions = job.fetch('permissions', {})
    abort "#{file}: #{name} has write permissions" if name != 'publish' && permissions.values.any? { |value| value == 'write' }
  end
  abort "#{file}: publisher lacks packages write" unless jobs['publish']['permissions']['packages'] == 'write'
  check_release_gate(file, jobs, 'publish')
  abort "#{file}: publisher cannot sign" unless jobs['publish']['permissions']['id-token'] == 'write' && jobs['publish']['permissions']['attestations'] == 'write'
  publisher = jobs['publish']['steps'].to_s
  abort "#{file}: publisher rebuilds" if publisher.include?('buildx build') || publisher.include?('build-push-action')
  abort "#{file}: publisher did not load frozen artifact" unless publisher.include?('actions/download-artifact@') && publisher.include?('image.sh publish')
  abort "#{file}: pushed digest is not signed" unless publisher.include?('cosign sign --yes') && publisher.include?('steps.push.outputs.digest')
  abort "#{file}: pushed digest lacks provenance" unless publisher.include?('actions/attest-build-provenance@') && publisher.include?('push-to-registry')
  abort "#{file}: native gate lacks exact-image script" unless jobs['native-gate']['steps'].to_s.include?('gate.sh')
  abort "#{file}: global absent-version check missing" unless jobs['prepublish']['steps'].to_s.include?('prepublish.sh')
  source = File.read(file)
  abort "#{file}: AWS or floating release reference" if source.match?(/\baws-actions\b|public\.ecr\.aws|:latest\b|:staging\b/)
  expected = kind == 'service' ? 7 : 6
  abort "#{file}: wrong image count" unless jobs['build']['strategy']['matrix']['name'].size == expected && jobs['publish']['strategy']['matrix']['name'].size == expected
end
{ 'cli' => 'publish-cli.yml', 'sdk' => 'publish-sdk.yml', 'chat' => 'publish-chat.yml' }.each do |kind, name|
  file = ".github/workflows/#{name}"
  jobs = YAML.load_file(file).fetch('jobs')
  check_release_gate(file, jobs, 'publish')
  abort "#{file}: tag version is not validated" unless jobs['publish']['steps'].to_s.include?("validate-tag.sh #{kind}")
end
ci = YAML.load_file('.github/workflows/image-build-check.yml')
abort 'build-only CI has publish permission' if ci.fetch('permissions').values.include?('write')
abort 'build-only CI missing native browser smoke' unless ci.fetch('jobs').key?('browser-smoke')
abort 'build-only CI missing toolchain coverage' unless ci.fetch('jobs').fetch('toolchain-build').fetch('strategy').fetch('matrix').fetch('name').size == 6
puts 'release workflow topology passed'
