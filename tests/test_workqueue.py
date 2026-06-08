# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn
from drgn.helpers.linux.cpumask import for_each_possible_cpu
from drgn.helpers.linux.kthread import kthread_data
from drgn.helpers.linux.percpu import per_cpu
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.pid import for_each_task

from drgn_tools import workqueue as wq
from tests import DrgnToolsTestCase
from tests import skip_live


def system_workqueue_names(prog: drgn.Program):
    # Pick some global workqueues that will always exist
    return {
        prog["system_wq"].name.string_(),
        prog["system_highpri_wq"].name.string_(),
        prog["system_long_wq"].name.string_(),
        prog["system_unbound_wq"].name.string_(),
        prog["system_freezable_wq"].name.string_(),
    }


class TestWorkqueue(DrgnToolsTestCase):
    def test_for_each_workqueue(self):
        # The found workqueue names should be a superset of the test names.
        wq_names = {
            workq.name.string_() for workq in wq.for_each_workqueue(self.prog)
        }
        self.assertGreaterEqual(wq_names, system_workqueue_names(self.prog))

    def test_for_each_pool(self):
        cpu0_normal_pool = per_cpu(self.prog["cpu_worker_pools"], 0)[
            0
        ].address_of_()
        cpu0_highprio_pool = per_cpu(self.prog["cpu_worker_pools"], 0)[
            1
        ].address_of_()
        all_pools = [pool for pool in wq.for_each_pool(self.prog)]
        self.assertIn(cpu0_normal_pool, all_pools)
        self.assertIn(cpu0_highprio_pool, all_pools)

    def test_for_each_worker(self):
        # for_each_worker() by design does not return rescue workers, which are
        # included when you scan the task list. So, filter them out here.
        kworker_tasks = [
            task.value_()
            for task in for_each_task(self.prog)
            if (
                task.flags & wq._PF_WQ_WORKER
                and not drgn.cast(
                    "struct worker *", kthread_data(task)
                ).rescue_wq
            )
        ]
        # Since commit 4cb1ef64609f9 ("workqueue: Implement BH workqueues to
        # eventually replace tasklets") in 6.9, some workers are BH (bottom
        # half). There's no task associated with these (obviously) so we just
        # need to skip them.
        kworker_obtained = [
            worker.task.value_()
            for worker in wq.for_each_worker(self.prog)
            if worker.task
        ]

        # The result is that this test only verifies that for_each_worker
        # returns the same non-BH, non-rescuer kthreads we would find by
        # scanning the task list.
        self.assertEqual(sorted(kworker_tasks), sorted(kworker_obtained))

    def test_for_each_pool_worker(self):
        test_pool = per_cpu(self.prog["cpu_worker_pools"], 0)[0].address_
        kworkers = [
            workers.value_()
            for workers in wq.for_each_worker(self.prog)
            if workers.pool.value_() == test_pool
        ]
        pool_kworkers = [
            workers.value_()
            for workers in wq.for_each_pool_worker(
                per_cpu(self.prog["cpu_worker_pools"], 0)[0].address_of_()
            )
        ]
        self.assertEqual(sorted(kworkers), sorted(pool_kworkers))

    def test_for_each_cpu_worker_pool(self):
        cpu0_worker_pools = [
            per_cpu(self.prog["cpu_worker_pools"], 0)[i].address_
            for i in [0, 1]
        ]
        worker_pools = [
            worker_pool.value_()
            for worker_pool in wq.for_each_cpu_worker_pool(self.prog, 0)
        ]
        self.assertEqual(worker_pools, cpu0_worker_pools)

    def test_for_each_pwq(self):
        workq = self.prog["system_wq"]
        pwqs = [pwq.value_() for pwq in wq.for_each_pwq(workq)]
        if hasattr(workq, "cpu_pwq"):
            # Commit ee1ceef727544 ("workqueue: Rename wq->cpu_pwqs to
            # wq->cpu_pwq") in v6.6 did the rename, and commit 687a9aa56f811
            # ("workqueue: Make per-cpu pool_workqueues allocated and released
            # like unbound ones") changed the semantic to be a double pointer.
            # These were in the same series, so we'll treat the rename as
            # evidence that the change should be used.
            cpu_pwqs_list = [
                per_cpu_ptr(workq.cpu_pwq, cpu)[0].value_()
                for cpu in for_each_possible_cpu(self.prog)
            ]
        else:
            cpu_pwqs_list = [
                per_cpu_ptr(workq.cpu_pwqs, cpu).value_()
                for cpu in for_each_possible_cpu(self.prog)
            ]
        self.assertCountEqual(pwqs, cpu_pwqs_list)

    @skip_live
    def test_for_each_pending_work_on_cpu(self):
        for work in wq.for_each_pending_work_on_cpu(self.prog, 0):
            pass

    @skip_live
    def test_for_each_pending_work_in_pool(self):
        pool = per_cpu(self.prog["cpu_worker_pools"], 0)[0].address_of_()
        for work in wq.for_each_pending_work_in_pool(pool):
            pass

    @skip_live
    def test_for_each_pending_work_of_pwq(self):
        cpu_pwqs_0 = wq.workqueue_get_pwq(self.prog["system_wq"], 0)
        for work in wq.for_each_pending_work_of_pwq(cpu_pwqs_0):
            pass

    @skip_live
    def test_show_all_workqueues(self):
        wq.show_all_workqueues(self.prog)

    @skip_live
    def test_show_unexpired_delayed_works(self):
        wq.show_unexpired_delayed_works(self.prog)
