"""Job queue for parallel vulnerability hunting."""

import queue
import threading
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class JobStatus(Enum):
    """Job status enum."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Job:
    """Represents a vulnerability hunting job."""
    job_id: str
    bug_class: str
    slice_data: Dict[str, Any]
    status: JobStatus = JobStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def __hash__(self):
        return hash(self.job_id)


class JobQueue:
    """Thread-safe job queue for parallel vulnerability hunting."""

    def __init__(self, max_size: int = 0):
        """Initialize job queue.
        
        Args:
            max_size: Maximum queue size (0 = unlimited)
        """
        self._queue = queue.Queue(maxsize=max_size)
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._job_counter = 0

    def add_job(self, bug_class: str, slice_data: Dict[str, Any]) -> Job:
        """Add a job to the queue.
        
        Args:
            bug_class: The vulnerability class to hunt for
            slice_data: The code slice to analyze
            
        Returns:
            The created Job
        """
        with self._lock:
            self._job_counter += 1
            job_id = f"job_{self._job_counter}_{bug_class.replace(' ', '_')}"
            
            job = Job(
                job_id=job_id,
                bug_class=bug_class,
                slice_data=slice_data
            )
            
            self._jobs[job_id] = job
            self._queue.put(job)
            
            return job

    def add_jobs(self, jobs: List[tuple]) -> List[Job]:
        """Add multiple jobs at once.
        
        Args:
            jobs: List of (bug_class, slice_data) tuples
            
        Returns:
            List of created Jobs
        """
        created_jobs = []
        for bug_class, slice_data in jobs:
            job = self.add_job(bug_class, slice_data)
            created_jobs.append(job)
        return created_jobs

    def get_job(self, block: bool = True, timeout: Optional[float] = None) -> Optional[Job]:
        """Get next job from queue.
        
        Args:
            block: Whether to block if queue is empty
            timeout: Timeout in seconds
            
        Returns:
            Next Job or None
        """
        try:
            job = self._queue.get(block=block, timeout=timeout)
            return job
        except queue.Empty:
            return None

    def mark_completed(self, job_id: str, result: Dict[str, Any]) -> None:
        """Mark a job as completed.
        
        Args:
            job_id: ID of the job
            result: The result data
        """
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = JobStatus.COMPLETED
                self._jobs[job_id].result = result

    def mark_failed(self, job_id: str, error: str) -> None:
        """Mark a job as failed.
        
        Args:
            job_id: ID of the job
            error: Error message
        """
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = JobStatus.FAILED
                self._jobs[job_id].error = error

    def get_job_by_id(self, job_id: str) -> Optional[Job]:
        """Get a job by its ID.
        
        Args:
            job_id: Job ID
            
        Returns:
            Job or None
        """
        with self._lock:
            return self._jobs.get(job_id)

    def get_all_jobs(self) -> List[Job]:
        """Get all jobs.
        
        Returns:
            List of all jobs
        """
        with self._lock:
            return list(self._jobs.values())

    def get_completed_jobs(self) -> List[Job]:
        """Get all completed jobs.
        
        Returns:
            List of completed jobs
        """
        with self._lock:
            return [j for j in self._jobs.values() if j.status == JobStatus.COMPLETED]

    def get_pending_count(self) -> int:
        """Get count of pending jobs.
        
        Returns:
            Number of pending jobs
        """
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.status == JobStatus.PENDING)

    def is_empty(self) -> bool:
        """Check if queue is empty.
        
        Returns:
            True if queue is empty
        """
        return self._queue.empty()

    def size(self) -> int:
        """Get queue size.
        
        Returns:
            Number of items in queue
        """
        return self._queue.qsize()


def create_job_queue(bug_classes: List[str], slices: List[Dict[str, Any]], max_slices: int = 20) -> JobQueue:
    """Create a job queue from bug classes and code slices.
    
    Args:
        bug_classes: List of vulnerability classes to hunt
        slices: List of code slices
        max_slices: Maximum number of slices to process
        
    Returns:
        Configured JobQueue
    """
    job_queue = JobQueue()
    
    # Limit slices
    slices_to_process = slices[:max_slices]
    
    # Create jobs: one job per bug class per slice
    jobs = []
    for slice_data in slices_to_process:
        for bug_class in bug_classes:
            jobs.append((bug_class, slice_data))
    
    job_queue.add_jobs(jobs)
    return job_queue
