package com.smartsca.adapter.outbound.maven;

import com.smartsca.application.port.outbound.DependencyResolver;
import com.smartsca.domain.analysis.*;
import com.smartsca.domain.component.DependencyGraph;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** CLI arguments are separate; only the bounded snapshot is mounted, read-only, inside Docker. */
public final class MavenDependencyResolver implements DependencyResolver {
    public static final String IMAGE = "smartsca-maven:3.9.9-jdk21-plugin3.11.0";
    public static final Map<String, String> VERSIONS = Map.of("jdk", "21.0.7+6", "maven", "3.9.9", "dependencyPlugin", "3.11.0", "image", IMAGE);
    private final FixtureProjectSource source;
    private final Duration timeout;
    public MavenDependencyResolver(FixtureProjectSource source, Duration timeout) {
        if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofMinutes(10)) > 0)
            throw new IllegalArgumentException("Tiempo de resolución admitido: hasta diez minutos.");
        this.source = source;
        this.timeout = timeout;
    }
    @Override public DependencyGraph resolve(Project project, AnalysisConfiguration configuration) {
        String name = "smartsca-analysis-" + UUID.randomUUID();
        Path temporary = null;
        try {
            temporary = Files.createTempDirectory("smartsca-analysis-");
            Path input = Files.createDirectory(temporary.resolve("input"));
            source.snapshot(project, configuration, input);
            var args = new ArrayList<>(List.of("docker", "run", "--detach", "--name", name, "--read-only",
                "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--cpus", "1", "--memory", "768m", "--memory-swap", "768m", "--pids-limit", "128",
                "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
                "--log-opt", "compress=false",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m,uid=1000,gid=1000",
                "--tmpfs", "/workspace:rw,noexec,nosuid,size=64m,uid=1000,gid=1000",
                "--env", "SMARTSCA_TIMEOUT_SECONDS=" + Math.max(1, timeout.toSeconds() + 30),
                "--label", "com.smartsca.analysis=true",
                "--mount", "type=bind,source=" + input + ",target=/input,readonly", IMAGE));
            if (!configuration.profiles().isEmpty()) args.add("-P" + String.join(",", new TreeSet<>(configuration.profiles())));
            if (!configuration.modules().contains(".")) {
                args.addAll(List.of("-pl", String.join(",", new TreeSet<>(configuration.modules())), "-am"));
            }
            command(args, Duration.ofSeconds(30));
            long deadline = System.nanoTime() + timeout.toNanos();
            while (true) {
                if (System.nanoTime() > deadline) throw new IllegalArgumentException("Maven excedió el tiempo máximo de ejecución.");
                String state = command(List.of("docker", "inspect", "--format", "{{.State.Status}}", name), Duration.ofSeconds(10)).strip();
                if (!state.equals("running")) {
                    throw new IllegalArgumentException("Maven no pudo resolver el proyecto. Revisa sus dependencias, perfiles y límites de recursos.");
                }
                String ready = command(List.of("docker", "exec", name, "sh", "-c",
                    "if test -f /workspace/success; then printf READY; else printf WAIT; fi"), Duration.ofSeconds(10));
                if (ready.equals("READY")) break;
                Thread.sleep(500);
            }
            Path archive = temporary.resolve("results.zip");
            capture(List.of("docker", "exec", name, "cat", "/workspace/results.zip"), archive);
            var outputs = new HashMap<String, String>();
            try (var zip = new java.util.zip.ZipInputStream(Files.newInputStream(archive))) {
                int count = 0;
                long total = 0;
                for (java.util.zip.ZipEntry entry; (entry = zip.getNextEntry()) != null;) {
                    if (++count > 4096 || entry.getName().startsWith("/") || Arrays.asList(entry.getName().split("/")).contains(".."))
                        throw new IllegalArgumentException("Archivo de resultados no admitido.");
                    byte[] bytes = zip.readNBytes(25 * 1024 * 1024 + 1);
                    total += bytes.length;
                    if (bytes.length > 25 * 1024 * 1024 || total > 64 * 1024 * 1024)
                        throw new IllegalArgumentException("Salida Maven demasiado grande.");
                    if (entry.getName().endsWith("target/smartsca-tree.json") || entry.getName().endsWith("target/smartsca-tree.tgf")) {
                        if (bytes.length > 5 * 1024 * 1024 || outputs.containsKey(entry.getName())) throw new IllegalArgumentException("Salida Maven no admitida.");
                        outputs.put(entry.getName(), new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
                    }
                }
            }
            var trees = new TreeMap<String, MavenTreeParser.Tree>();
            Set<String> selected = configuration.modules().contains(".") ? project.modules() : configuration.modules();
            for (String module : selected) {
                String prefix = module.equals(".") ? "" : module + "/";
                String json = outputs.get(prefix + "target/smartsca-tree.json"), tgf = outputs.get(prefix + "target/smartsca-tree.tgf");
                if (json == null || tgf == null) throw new IllegalArgumentException("No se obtuvo la resolución de un módulo requerido.");
                trees.put(module, new MavenTreeParser.Tree(json, tgf));
            }
            // Keep connector paths; configured scopes filter inventory/analysis rather than stored Maven evidence.
            return new MavenTreeParser().parse(trees, AnalysisConfiguration.SUPPORTED_SCOPES);
        } catch (IllegalArgumentException error) { throw error; }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new IllegalArgumentException("Resolución interrumpida."); }
        catch (Exception error) { throw new IllegalArgumentException("No se pudo ejecutar Maven aislado. Comprueba Docker y la imagen de análisis."); }
        finally {
            boolean interrupted = Thread.interrupted();
            try { command(List.of("docker", "rm", "--force", name), Duration.ofSeconds(15)); } catch (Exception ignored) { }
            if (temporary != null) try (var paths = Files.walk(temporary)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
            } catch (java.io.IOException ignored) { }
            if (interrupted) Thread.currentThread().interrupt();
        }
    }
    private static void capture(List<String> args, Path archive) throws Exception {
        var process = new ProcessBuilder(args).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        var failure = new java.util.concurrent.atomic.AtomicReference<Exception>();
        Thread reader = Thread.ofVirtual().start(() -> {
            try (var input = process.getInputStream(); var output = Files.newOutputStream(archive)) {
                byte[] bytes = new byte[8192];
                long total = 0;
                for (int n; (n = input.read(bytes)) != -1;) {
                    total += n;
                    if (total > 32 * 1024 * 1024) throw new IllegalArgumentException("Archivo de resultados demasiado grande.");
                    output.write(bytes, 0, n);
                }
            } catch (Exception error) { failure.set(error); process.destroyForcibly(); }
        });
        try {
            if (!process.waitFor(30, TimeUnit.SECONDS)) throw new IllegalArgumentException("No se pudieron recuperar los resultados a tiempo.");
            reader.join(2000);
            if (failure.get() != null || reader.isAlive() || process.exitValue() != 0) throw new IllegalArgumentException("No se pudieron recuperar los resultados Maven.");
        } finally { process.destroyForcibly(); }
    }
    static String command(List<String> arguments, Duration timeout) throws Exception {
        var process = new ProcessBuilder(arguments).redirectErrorStream(true).start();
        var output = new java.io.ByteArrayOutputStream();
        Thread reader = Thread.ofVirtual().start(() -> {
            try (var input = process.getInputStream()) {
                byte[] bytes = new byte[4096];
                for (int n; (n = input.read(bytes)) != -1;) if (output.size() < 65_536) output.write(bytes, 0, Math.min(n, 65_536 - output.size()));
            } catch (java.io.IOException ignored) { }
        });
        try {
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) throw new IllegalArgumentException("Maven/Docker excedió el tiempo máximo de ejecución.");
            reader.join(2000);
            if (process.exitValue() != 0) {
                System.getLogger(MavenDependencyResolver.class.getName()).log(System.Logger.Level.WARNING, output.toString(java.nio.charset.StandardCharsets.UTF_8));
                throw new IllegalArgumentException("La operación Docker falló. Comprueba el motor y la imagen de análisis.");
            }
            return output.toString(java.nio.charset.StandardCharsets.UTF_8);
        } finally { process.destroyForcibly(); }
    }
}
