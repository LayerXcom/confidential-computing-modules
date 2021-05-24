const simpleGit = require('simple-git');

module.exports = async ({ github, path }) => {

    const git = simpleGit(path);
    const logs = await git.tags({ '--sort': '-v:refname' })
        .then((t) => {
            const tags = t.all.slice(0, 2);
            return git.log({ 'from': tags[0], 'to': tags[1] })
        });
    console.log(logs);

    const { data } = await github.pulls.list({
        owner: 'LayerXcom',
        repo: 'anonify',
        base: 'main',
        state: 'closed',
    })
    const res = data.map(d => {
        return {
            title: d.title,
            url: d.html_url,
            number: d.number,
            merge_commit_sha: d.merge_commit_sha,
        }
    });
    return res.filter(d => logs.all.some(l => l.hash === d.merge_commit_sha))
        .map(pr => `- [#${pr.number}](${pr.url}) ${pr.title}`)
        .join('\n');
}