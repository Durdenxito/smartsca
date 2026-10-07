package com.smartsca.adapter.outbound;

import java.net.URI;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Fixed provider endpoints, bounded bodies/deadlines, one transient retry and a small TTL cache. */
public final class ExternalJsonClient {
    public record Response(JsonNode json, Instant collectedAt) {}
    public record Document(byte[] bytes, Instant collectedAt) {
        public Document { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER).build();
    private final JsonMapper json = JsonMapper.builder().build();
    private final Map<String, Document> cache = new LinkedHashMap<>();
    private final boolean enabled;
    public ExternalJsonClient(boolean enabled) { this.enabled = enabled; }
    public static long deadline() { return System.nanoTime() + Duration.ofSeconds(60).toNanos(); }

    public synchronized Response request(URI uri, Object payload, long deadline) {
        var response = document(uri, payload, deadline);
        try {
            var node = json.readTree(response.bytes());
            if (node == null || !node.isObject()) throw new IllegalArgumentException("Respuesta JSON externa inválida.");
            return new Response(node, response.collectedAt());
        } catch (RuntimeException error) {
            cache.remove(uri + "\n" + (payload == null ? null : json.writeValueAsString(payload)));
            throw error;
        }
    }
    // ponytail: serialize the bounded provider cache; split locks if several workers need simultaneous HTTP.
    public synchronized Document document(URI uri, Object payload, long deadline) {
        if (!enabled) throw new IllegalArgumentException("Consulta externa deshabilitada para este entorno.");
        if (!("https".equals(uri.getScheme()) || ("http".equals(uri.getScheme()) && "127.0.0.1".equals(uri.getHost())))
            || uri.getUserInfo() != null) throw new IllegalArgumentException("Endpoint externo no admitido.");
        String body = payload == null ? null : json.writeValueAsString(payload);
        String key = uri + "\n" + body;
        var cached = cache.get(key);
        if (cached != null && cached.collectedAt().plusSeconds(900).isAfter(Instant.now())) return cached;
        for (int attempt = 0; attempt < 2; attempt++) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0 || Thread.currentThread().isInterrupted()) throw new IllegalArgumentException("Se agotó el tiempo de consulta externa.");
            var timeout = Duration.ofNanos(Math.min(remaining, Duration.ofSeconds(10).toNanos()));
            var request = HttpRequest.newBuilder(uri).timeout(timeout).header("Accept", "application/json, application/xml")
                .header("User-Agent", "SmartSCA/0.0.1");
            if (body == null) request.GET();
            else request.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
            var future = client.sendAsync(request.build(), ignored -> limitedBody());
            try {
                var response = future.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
                int code = response.statusCode();
                if ((code == 429 || code >= 500) && attempt == 0) { Thread.sleep(200); continue; }
                if (code != 200) throw new IllegalArgumentException("La fuente respondió HTTP " + code + ".");
                var result = new Document(response.body(), Instant.now());
                // Up to 16 responses of 8 MiB; evict oldest entries, never reuse errors or expired data.
                if (cache.size() >= 16) cache.remove(cache.keySet().iterator().next());
                cache.put(key, result);
                return result;
            } catch (InterruptedException error) {
                future.cancel(true); Thread.currentThread().interrupt();
                throw new IllegalArgumentException("Consulta externa interrumpida.");
            } catch (ExecutionException | TimeoutException error) {
                future.cancel(true);
                if (attempt == 1) throw new IllegalArgumentException("La fuente no respondió a tiempo o excedió los límites.");
            }
        }
        throw new IllegalArgumentException("No se pudo consultar la fuente externa.");
    }

    private static HttpResponse.BodySubscriber<byte[]> limitedBody() {
        var delegate = HttpResponse.BodySubscribers.ofByteArray();
        return new HttpResponse.BodySubscriber<>() {
            private Flow.Subscription subscription;
            private long bytes;
            @Override public CompletionStage<byte[]> getBody() { return delegate.getBody(); }
            @Override public void onSubscribe(Flow.Subscription value) { subscription = value; delegate.onSubscribe(value); }
            @Override public void onNext(List<ByteBuffer> buffers) {
                for (var buffer : buffers) bytes += buffer.remaining();
                if (bytes > 8 * 1024 * 1024) {
                    subscription.cancel(); delegate.onError(new IllegalArgumentException("Respuesta externa demasiado grande."));
                } else delegate.onNext(buffers);
            }
            @Override public void onError(Throwable error) { delegate.onError(error); }
            @Override public void onComplete() { delegate.onComplete(); }
        };
    }
}
