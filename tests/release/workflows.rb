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
  expected = kind == 'service' ? 8 : 6
  abort "#{file}: wrong image count" unless jobs['build']['strategy']['matrix']['name'].size == expected && jobs['publish']['strategy']['matrix']['name'].size == expected
end
{ 'cli' => 'publish-cli.yml', 'sdk' => 'publish-sdk.yml', 'chat' => 'publish-chat.yml' }.each do |kind, name|
  file = ".github/workflows/#{name}"
  jobs = YAML.load_file(file).fetch('jobs')
  check_release_gate(file, jobs, 'publish')
  # The pack job validates the tag and builds the tarball the publisher uploads.
  abort "#{file}: publisher does not take the packed tarball" unless Array(jobs['publish']['needs']).include?('pack')
  abort "#{file}: tag version is not validated" unless jobs.fetch('pack')['steps'].to_s.include?("validate-tag.sh #{kind}")
end
services = YAML.load_file(files['service']).dig('jobs', 'build', 'strategy', 'matrix', 'name')
gate = YAML.load_file(files['service']).dig('jobs', 'native-gate', 'steps').to_s
abort "#{files['service']}: native gate does not load the migrate artifact" unless gate.include?('service-migrate')
abort 'gate.sh does not check the migrate image' unless File.read('scripts/release/gate.sh').include?('release_check_migrate_image')
abort 'gate.sh does not check the runner preload' unless File.read('scripts/release/gate.sh').include?('release_check_worker_nodump "$worker_ref"')
ci = YAML.load_file('.github/workflows/image-build-check.yml')
abort 'build-only CI has publish permission' if ci.fetch('permissions').values.include?('write')
checked = ci.fetch('jobs').fetch('build').fetch('strategy').fetch('matrix').fetch('include').map { |entry| entry['service'] }
abort "build-only CI misses service images: #{(services - checked).join(', ')}" unless (services - checked).empty?
abort 'build-only CI does not check the migrate image' unless ci.fetch('jobs').fetch('build').fetch('steps').to_s.include?('release_check_migrate_image')
abort 'build-only CI does not check the runner preload' unless ci.fetch('jobs').fetch('build').fetch('steps').to_s.include?('release_check_worker_nodump eve-horizon/worker:check')
abort 'build-only CI missing native browser smoke' unless ci.fetch('jobs').key?('browser-smoke')
abort 'build-only CI does not run the release script tests' unless ci.fetch('jobs').fetch('release-scripts', {}).fetch('steps', []).to_s.include?('scripts/release/check.sh')
abort 'build-only CI missing toolchain coverage' unless ci.fetch('jobs').fetch('toolchain-build').fetch('strategy').fetch('matrix').fetch('name').size == 6
puts 'release workflow topology passed'
