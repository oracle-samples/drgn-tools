# Copyright (c) 2023, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import drgn_tools.runq as runq
from tests import DrgnToolsTestCase
from tests import skip_live


class TestRunq(DrgnToolsTestCase):
    @skip_live
    def test_run_queue(self):
        runq.run_queue(self.prog)
