// Package telemetry initialises an OpenTelemetry TracerProvider for the
// populist-abci process.
//
// Configuration (all via environment variables — set in systemd unit):
//
//	OTEL_EXPORTER_OTLP_ENDPOINT  — ADOT Collector HTTP endpoint (default: disabled)
//	OTEL_SERVICE_NAME             — service.name resource attribute
//	OTEL_RESOURCE_ATTRIBUTES      — comma-separated key=value pairs
//
// If OTEL_EXPORTER_OTLP_ENDPOINT is empty the function returns a no-op
// provider so the binary runs cleanly without a running ADOT Collector.
//
// Propagation uses W3C TraceContext + Baggage headers. The ADOT Collector
// converts these to AWS X-Ray format (1-<unix_time_hex>-<random_96bit>)
// on export — no application-level X-Ray SDK required.
//
// PII guardrail: span attributes must NEVER include identity_hash,
// didit_proof_hash, or ballot_nonce. The ADOT filter/pii processor is
// the backstop at the collector layer.
package telemetry

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Init initialises the global OTel TracerProvider and returns a shutdown function.
// Call shutdown(ctx) on process exit to flush pending spans.
func Init(ctx context.Context, serviceName string) (trace.TracerProvider, func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		p := noop.NewTracerProvider()
		otel.SetTracerProvider(p)
		return p, func(context.Context) error { return nil }, nil
	}

	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // localhost only; TLS is between ADOT and AWS
	)
	if err != nil {
		return nil, nil, err
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		res = resource.Default()
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		// 10% sampling for consensus — block production is high-frequency
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1))),
	)

	// W3C TraceContext + Baggage. ADOT Collector converts to X-Ray format on export.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, tp.Shutdown, nil
}

// Tracer returns a named tracer from the global provider.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}
