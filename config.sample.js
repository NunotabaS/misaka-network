{
  "providers": [
    {
      "type": "github-gist",
      "secret": "This is the initial mixin secret",
      "hash": "sha1",
      "probes": 1024,
      "probe_order": "standard",
      "headers": {
        "User-Agent": "MisakaNetwork/1.0"
      },
      "templates": {
        "user": "u{hash:6.6}",
        "mixing": "previous = {previous} | secret = {secret}"
      }
    }
  ]
}