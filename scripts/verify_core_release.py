"""Reuse only completed main CI for this exact immutable core commit."""
import json
import os
import urllib.request

REQUIRED = {'plan', 'Dependency policy', 'Race, coverage and CLI smoke test',
            'Accepted validation plan'} | {f'{platform} / Go {version}'
    for platform in ('ubuntu-24.04', 'windows-2022', 'macos-15')
    for version in ('1.26.10', '1.27.3')}


def validate(run, jobs, sha):
    if (run.get('head_sha') != sha or run.get('head_branch') != 'main'
            or run.get('event') != 'push' or run.get('status') != 'completed'
            or run.get('conclusion') != 'success'):
        raise ValueError('release requires successful exact-commit main push CI')
    if len(jobs) != len(REQUIRED) or {j.get('name') for j in jobs} != REQUIRED:
        raise ValueError('release CI job set is incomplete or unexpected')
    if any(j.get('status') != 'completed' or j.get('conclusion') != 'success' for j in jobs):
        raise ValueError('release CI contains failed, skipped or incomplete jobs')


def api(path):
    request = urllib.request.Request('https://api.github.com/repos/'+os.environ['GITHUB_REPOSITORY']+path,
        headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],
                 'Accept':'application/vnd.github+json','User-Agent':'fastls-core-release'})
    with urllib.request.urlopen(request, timeout=35) as response:
        return json.load(response)


def main():
    sha=os.environ['GITHUB_SHA']
    runs=api('/actions/workflows/ci.yml/runs?head_sha='+sha+'&event=push&per_page=100')['workflow_runs']
    for run in runs:
        if run.get('head_branch') != 'main' or run.get('conclusion') != 'success':
            continue
        jobs=api('/actions/runs/'+str(run['id'])+'/jobs?per_page=100')['jobs']
        validate(run,jobs,sha)
        print(json.dumps({'source':sha,'reused_ci':run['html_url'],'required_jobs':sorted(REQUIRED)}))
        return
    raise RuntimeError('no successful exact-commit main candidate; finish CI before tagging')

if __name__ == '__main__':
    main()
