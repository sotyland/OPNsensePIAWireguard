import unittest
from PureVPNMonitor import decision


class RecoveryDecisionTests(unittest.TestCase):
    def test_healthy_overrides_backoff(self):
        self.assertEqual(decision(1000, 990, {'next_retry': 2000}), 'healthy')

    def test_stale_requires_two_observations(self):
        self.assertEqual(decision(1000, 0, {}), 'suspect')
        self.assertEqual(decision(1060, 0, {'misses': 1}), 'recover')

    def test_backoff_prevents_restart_storm(self):
        self.assertEqual(decision(1000, 0, {'misses': 1, 'next_retry': 1100}), 'cooldown')

    def test_future_handshake_is_not_healthy(self):
        self.assertEqual(decision(1000, 1100, {}), 'suspect')


if __name__ == '__main__':
    unittest.main()
