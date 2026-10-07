package com.smartsca.adapter.inbound.job;
import com.smartsca.application.port.inbound.RunPendingAnalysesUseCase;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;

/** Polls persisted work within the same backend process. */
public class AnalysisWorker {
    private final RunPendingAnalysesUseCase useCase;
    private volatile boolean ready;
    public AnalysisWorker(RunPendingAnalysesUseCase useCase) { this.useCase = useCase; }
    @EventListener(ApplicationReadyEvent.class) public void recover() { useCase.failInterrupted(); ready = true; }
    @Scheduled(fixedDelayString = "${smartsca.worker.poll-ms:1000}") public void poll() { if (ready) useCase.runPending(4); }
}
