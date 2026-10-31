content = """# API Data Contracts

Stored fields from Parquet. Computed: pagination total. JSON fields are strings containing JSON. Nulls as null. Timeline preserves eventtime/date/time/tz. Graph node type/value/id; edge source/target/rel/evidence/line/observed.
"""
open("C:/Users/nsrn/Desktop/scaratch/docs/api-data-contracts.md","w").write(content)
content = """# API Performance Plan

DuckDB projections/predicates. limit default 50 max 200. Large offset risk. Connection per request. Bounded memory. Graph filter subset. Benchmarks 1K/1M/large not measured.
"""
open("C:/Users/nsrn/Desktop/scaratch/docs/api-performance-plan.md","w").write(content)
print("ok")
