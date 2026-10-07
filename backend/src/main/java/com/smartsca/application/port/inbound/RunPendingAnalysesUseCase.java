package com.smartsca.application.port.inbound;
public interface RunPendingAnalysesUseCase {
    void runPending(int maxConcurrent);
    void failInterrupted();
}
