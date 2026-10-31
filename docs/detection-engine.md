# Detection Engine

# Detection Engine

The Python engine reads only the Parquet columns needed by the rule evaluator and processes
input in bounded Arrow batches. Rules are compiled once and indexed by event type/subtype,
so an event is evaluated only against eligible rules. Detection output is buffered in
4,096-row Parquet groups rather than writing one row per match.

Run with `python engine.py --input <events.parquet> --rules rules/detections.yaml
--output <detections.parquet> --batch-size 5000`. `--batch-size` controls input rows
per Arrow batch; the output buffer remains bounded independently. Rules and output
semantics are unchanged by this optimization.

See [detection-benchmark.md](../reports/detection-benchmark.md) for the measured sample
results and limits of the available accuracy evidence.
