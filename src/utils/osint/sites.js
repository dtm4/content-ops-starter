// Username-check site definitions (Sherlock-style).
// errorType:
//   status_code - profile exists if HTTP 2xx, missing on 404
//   message     - profile missing if the response body contains `errorMsg`
//   json_status - an API endpoint; 2xx = exists
// `url` is the human profile link, `probe` (optional) is what we actually request.

const sites = [
    { name: 'GitHub', category: 'dev', url: 'https://github.com/{}', probe: 'https://api.github.com/users/{}', errorType: 'json_status' },
    { name: 'GitLab', category: 'dev', url: 'https://gitlab.com/{}', probe: 'https://gitlab.com/api/v4/users?username={}', errorType: 'message', errorMsg: '[]' },
    { name: 'Bitbucket', category: 'dev', url: 'https://bitbucket.org/{}/', errorType: 'status_code' },
    { name: 'Docker Hub', category: 'dev', url: 'https://hub.docker.com/u/{}', probe: 'https://hub.docker.com/v2/users/{}/', errorType: 'json_status' },
    { name: 'npm', category: 'dev', url: 'https://www.npmjs.com/~{}', errorType: 'status_code' },
    { name: 'PyPI', category: 'dev', url: 'https://pypi.org/user/{}/', errorType: 'status_code' },
    { name: 'Dev.to', category: 'dev', url: 'https://dev.to/{}', errorType: 'status_code' },
    { name: 'Codeberg', category: 'dev', url: 'https://codeberg.org/{}', errorType: 'status_code' },
    { name: 'Keybase', category: 'dev', url: 'https://keybase.io/{}', probe: 'https://keybase.io/_/api/1.0/user/lookup.json?usernames={}', errorType: 'message', errorMsg: '"them":[null]' },
    { name: 'HackerNews', category: 'dev', url: 'https://news.ycombinator.com/user?id={}', probe: 'https://hacker-news.firebaseio.com/v0/user/{}.json', errorType: 'message', errorMsg: 'null' },
    { name: 'Reddit', category: 'social', url: 'https://www.reddit.com/user/{}', probe: 'https://www.reddit.com/user/{}/about.json', errorType: 'json_status' },
    { name: 'Medium', category: 'social', url: 'https://medium.com/@{}', errorType: 'status_code' },
    { name: 'Mastodon (mastodon.social)', category: 'social', url: 'https://mastodon.social/@{}', probe: 'https://mastodon.social/api/v1/accounts/lookup?acct={}', errorType: 'json_status' },
    { name: 'Bluesky', category: 'social', url: 'https://bsky.app/profile/{}.bsky.social', probe: 'https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}.bsky.social', errorType: 'json_status' },
    { name: 'Pinterest', category: 'social', url: 'https://www.pinterest.com/{}/', errorType: 'status_code' },
    { name: 'Tumblr', category: 'social', url: 'https://{}.tumblr.com/', errorType: 'status_code' },
    { name: 'WordPress', category: 'social', url: 'https://{}.wordpress.com/', errorType: 'status_code' },
    { name: 'Gravatar', category: 'social', url: 'https://gravatar.com/{}', probe: 'https://en.gravatar.com/{}.json', errorType: 'json_status' },
    { name: 'About.me', category: 'social', url: 'https://about.me/{}', errorType: 'status_code' },
    { name: 'Linktree', category: 'social', url: 'https://linktr.ee/{}', errorType: 'status_code' },
    { name: 'SoundCloud', category: 'media', url: 'https://soundcloud.com/{}', errorType: 'status_code' },
    { name: 'Vimeo', category: 'media', url: 'https://vimeo.com/{}', errorType: 'status_code' },
    { name: 'Behance', category: 'media', url: 'https://www.behance.net/{}', errorType: 'status_code' },
    { name: 'Dribbble', category: 'media', url: 'https://dribbble.com/{}', errorType: 'status_code' },
    { name: 'Flickr', category: 'media', url: 'https://www.flickr.com/people/{}', errorType: 'status_code' },
    { name: 'Chess.com', category: 'gaming', url: 'https://www.chess.com/member/{}', probe: 'https://api.chess.com/pub/player/{}', errorType: 'json_status' },
    { name: 'Lichess', category: 'gaming', url: 'https://lichess.org/@/{}', probe: 'https://lichess.org/api/user/{}', errorType: 'json_status' },
    { name: 'Steam', category: 'gaming', url: 'https://steamcommunity.com/id/{}', errorType: 'message', errorMsg: 'The specified profile could not be found' },
    { name: 'Speedrun.com', category: 'gaming', url: 'https://www.speedrun.com/users/{}', probe: 'https://www.speedrun.com/api/v1/users/{}', errorType: 'json_status' },
    { name: 'Kaggle', category: 'dev', url: 'https://www.kaggle.com/{}', errorType: 'status_code' },
    { name: 'Replit', category: 'dev', url: 'https://replit.com/@{}', errorType: 'status_code' },
    { name: 'Patreon', category: 'other', url: 'https://www.patreon.com/{}', errorType: 'status_code' },
    { name: 'Ko-fi', category: 'other', url: 'https://ko-fi.com/{}', errorType: 'status_code' },
    { name: 'Product Hunt', category: 'other', url: 'https://www.producthunt.com/@{}', errorType: 'status_code' }
];

export default sites;
