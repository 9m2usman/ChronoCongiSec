"""
Performance Benchmark Tests for Phase 5 Containment System.

This module tests the performance of containment-related operations.
"""

import asyncio
import time
import pytest
from backend.app.memory import retrieve_memory
from backend.app.security.quarantine import QuarantineWorkflow
from backend.tests.security.conftest import AGENT, T_A, World, make_ctx

# Contexts
ANALYST = make_ctx(role="SECURITY_ANALYST", user="analyst-1")


class BenchmarkEnv:
    def __init__(self):
        self.w = World()
        self.wf = QuarantineWorkflow(self.w.trust, self.w.repo)
        self.benchmark_results = {}

    def create_memory_record(self, content="Test memo content"):
        return self.w.memory(content=content, agent_id=AGENT)

    async def quarantine_benchmark(self, num_records=100):
        records = [
            self.w.memory(content=f"Record {i}", agent_id=AGENT)
            for i in range(num_records)
        ]

        start_time = time.time()
        for record in records:
            await self.wf.quarantine(
                ANALYST, {"record_id": record, "reason": "Benchmark quarantine"}
            )

        end_time = time.time()
        return end_time - start_time

    def get_benchmark_results(self):
        return self.benchmark_results


@pytest.fixture
def env():
    return BenchmarkEnv()


def test_quarantine_benchmark(env):
    num_records = 100
    quarantine_time = asyncio.run(env.quarantine_benchmark(num_records))
    env.benchmark_results["quarantine_time_for_100_records"] = quarantine_time
    print(f"Quarantine time for {num_records} records: {quarantine_time:.4f} seconds")

    # Ensure quarantine completes without errors
    assert quarantine_time > 0

    # Verify no records are retrievable after quarantine
    records = [
        r.id for r in retrieve_memory(T_A, limit=num_records, repository=env.w.repo)
    ]
    assert len(records) == 0
