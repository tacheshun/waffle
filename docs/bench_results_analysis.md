# Benchmark Results Analysis
The benchmark results show that the Waffle package is very performant:
- Creating a new Waffle instance: ~341 ns/op
- Adding a rule: ~48 ns/op
- Processing a request with no rules: ~37 ns/op
- Processing a request with rules: ~57 ns/op
- Using the HandlerFunc middleware: ~32 ns/op

These are excellent performance numbers, indicating that the Waffle WAF implementation is very efficient and suitable for production use.