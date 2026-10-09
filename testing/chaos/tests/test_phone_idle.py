"""Reject ambiguous power state and exercise the real shell restoration fence."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from sim.phone_idle import IdleGuard, foreground_network_policy, guard_script, idle_state


class PhoneIdleTests(unittest.TestCase):
    def test_network_policy_requires_observed_foreground_doze_allowance(self):
        text = ('Device idle: true\n'
                ' UID=12345 state={procState=FGS ,seq=1,cap=NF} '
                'blocked_state={blocked=DOZE|APP_BACKGROUND,allowed=FOREGROUND,effective=NONE}')
        self.assertEqual(foreground_network_policy(text, 12345)['effective'], 'NONE')
        for changed in (text.replace('true', 'false'), text.replace('12345', '12346'),
                        text.replace('FGS', 'TOP'), text.replace('DOZE|', ''),
                        text.replace('FOREGROUND', 'POWER_SAVE_ALLOWLIST'),
                        text.replace('effective=NONE', 'effective=DOZE'), text + '\n' + text):
            with self.subTest(text=changed), self.assertRaises(RuntimeError):
                foreground_network_policy(changed, 12345)

    def test_idle_state_requires_one_complete_observation(self):
        self.assertEqual(idle_state('mForceIdle=true mState=IDLE mLightState=OVERRIDE'),
                         {'forced': True, 'deep': 'IDLE', 'light': 'OVERRIDE'})
        for text in ('', 'mForceIdle=false mState=ACTIVE',
                     'mForceIdle=true mForceIdle=false mState=IDLE mLightState=IDLE'):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                idle_state(text)

    def test_manual_request_and_watchdog_restore_only_the_owned_idle_test(self):
        for owner, manual in (('ours', False), ('ours', True), ('another', True)):
            with self.subTest(owner=owner, manual=manual), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'owner').write_text(owner)
                if manual:
                    (root / 'restore').touch()
                command = root / 'dumpsys'
                command.write_text('#!/bin/sh\ntest "$*" = "deviceidle unforce"\necho restored\n')
                command.chmod(0o700)
                result = subprocess.run(['sh'], input=guard_script(root, 'ours', seconds=1),
                                        text=True, capture_output=True, timeout=5,
                                        env={**os.environ, 'PATH': str(root) + ':' + os.environ['PATH']})
                self.assertEqual(result.returncode == 0, owner == 'ours')
                self.assertEqual((root / 'done').exists(), owner == 'ours')
                self.assertEqual((root / 'restore.log').exists(), owner == 'ours')

    def test_controller_cannot_restore_another_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'owner').write_text('another')
            phone = Mock()

            def shell(*args):
                result = subprocess.run(args, capture_output=True, timeout=5)
                if result.returncode:
                    raise RuntimeError('ownership rejected')
                return result.stdout

            phone.shell.side_effect = shell
            guard = IdleGuard(phone)
            guard.directory, guard.token, guard.attempted = str(root), 'ours', True
            with self.assertRaisesRegex(RuntimeError, 'ownership rejected'):
                guard.restore()
            self.assertFalse((root / 'restore').exists())
