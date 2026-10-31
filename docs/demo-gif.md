# Generating the demo GIF (`assets/demo.gif`)

The README references `assets/demo.gif`. The GIF is not committed until it is
recorded from a real run; generate it with one of the options below.

## Option 1: VHS (recommended)

[VHS](https://github.com/charmbracelet/vhs) renders a GIF from a script.

```bash
python examples/create_demo_repo.py     # builds examples/demo_repo with tags v0.1.0 and v0.2.0
pip install -e .
vhs docs/demo.tape                      # writes assets/demo.gif
```

The script is [`demo.tape`](demo.tape). It runs `athena breaking-changes` against
the demo repository, so the output shown is real tool output.

## Option 2: asciinema + agg

```bash
python examples/create_demo_repo.py
asciinema rec demo.cast -c "athena breaking-changes examples/demo_repo --base v0.1.0 --target v0.2.0"
agg demo.cast assets/demo.gif           # https://github.com/asciinema/agg
```

Keep the GIF under roughly 2 MB and under 15 seconds so it loads inline on GitHub.
