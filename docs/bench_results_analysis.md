# Benchmark Results Analysis
## Instance Creation
* BenchmarkWaffleNew: ~346.3 ns/op with 544 B/op and 11 allocs/op
* This is the baseline cost of creating a new Waffle instance with default settings
* BenchmarkWaffleNewWithOptions: ~63.66 ns/op with 144 B/op and 2 allocs/op
* Creating a Waffle instance with custom options is significantly faster (5.4x) and uses less memory
* This suggests that using custom options is more efficient than relying on defaults
## Rule Management
* BenchmarkWaffleAddRule: ~52.87 ns/op with 85 B/op and 0 allocs/op
* Adding rules to a Waffle instance is very efficient with minimal memory overhead
## Request Processing
* BenchmarkWaffleProcessNoRules: ~5.246 ns/op with 0 B/op and 0 allocs/op
* Processing a request with no rules is extremely fast with zero memory allocations
* BenchmarkWaffleProcessWithRules: ~6.821 ns/op with 0 B/op and 0 allocs/op
* Having rules that don't match adds only ~1.6 ns overhead, which is negligible
* BenchmarkWaffleProcessWithMatchingRule: ~4621 ns/op with 48 B/op and 1 allocs/op
* When a rule matches, processing time increases significantly due to the block handling
* This is expected as it's performing the actual security function
## Middleware Performance
* BenchmarkWaffleMiddleware: ~9.402 ns/op with 0 B/op and 0 allocs/op
* The middleware wrapper adds minimal overhead when no rules are present
* BenchmarkWaffleMiddlewareWithRules: ~10.24 ns/op with 0 B/op and 0 allocs/op
* Adding rules that don't match adds only ~0.8 ns overhead to the middleware
* BenchmarkWaffleMiddlewareWithMatchingRule: ~4603 ns/op with 183 B/op and 2 allocs/op
* Similar to direct processing, matching rules in middleware increases processing time
* The memory usage is slightly higher than direct processing (183 B vs 48 B)
* BenchmarkWaffleHandlerFunc: ~8.362 ns/op with 0 B/op and 0 allocs/op
* The HandlerFunc middleware is very efficient, even slightly faster than the standard middleware