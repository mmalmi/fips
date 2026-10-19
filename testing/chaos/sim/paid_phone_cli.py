"""Select one bounded phone acceptance workload."""

import argparse
import os
from pathlib import Path
import signal
import traceback

from .paid_phone import PaidPhoneRun


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--mint-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--phone-restart', action='store_true',
                      help='force-stop and reopen the app between two paid cohorts')
    mode.add_argument('--load', action='store_true',
                      help='five minutes of bidirectional traffic with a controlled loss window')
    mode.add_argument('--transit', action='store_true',
                      help='paid router → phone → router → router on the existing LAN')
    parser.add_argument('--screen-off', action='store_true',
                        help='also test transit with the screen off; operator unlock is needed afterward')
    parser.add_argument('--sustained-transit', action='store_true',
                        help='transfer nine MiB per direction through the background phone for at least five minutes')
    parser.add_argument('--compare-transit-rates', action='store_true',
                        help='compare four MiB per direction in five-minute background windows at 32 and 256 KiB/s')
    parser.add_argument('--forced-idle', action='store_true',
                        help='verify paid foreground-service transit during and after forced Android Doze')
    parser.add_argument('--natural-idle', action='store_true',
                        help='wait up to one hour for real unplugged deep idle, then test fresh paid transit')
    parser.add_argument('--phone-outage', action='store_true',
                        help='cut one phone UDP link, verify peer loss, then recover original paid channels')
    parser.add_argument('--impaired-transit', nargs='?', const='drop', choices=('drop', 'corrupt'),
                        help='drop isolated packets or corrupt eight-frame bursts on one phone UDP link')
    parser.add_argument('--phone-renewal', nargs='?', const='reconnect',
                        choices=('reconnect', 'sustained'),
                        help='renew during a held close and reconnect, or ten minutes of background traffic')
    parser.add_argument('--phone-expiry', action='store_true',
                        help='restart the phone after expiry and recover its buyer and seller channels')
    parser.add_argument(
        '--open-mesh', action='store_true',
        help='use the existing guarded temporary open radio profile',
    )
    args = parser.parse_args()
    for name in ('screen_off', 'sustained_transit', 'compare_transit_rates',
                 'forced_idle', 'natural_idle', 'phone_outage', 'phone_renewal', 'phone_expiry'):
        if getattr(args, name) and not args.transit:
            parser.error('--' + name.replace('_', '-') + ' requires --transit')
    if args.impaired_transit and not (args.transit and args.sustained_transit):
        parser.error('--impaired-transit requires --transit --sustained-transit')
    os.umask(0o077)
    seconds = 5400 if args.natural_idle else 1500 if args.load else 1200

    def deadline(_signal, _frame):
        raise TimeoutError(f'phone mesh acceptance exceeded {seconds} seconds')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(seconds)
    if args.natural_idle:
        from .phone_natural_idle import NaturalIdleRun
        run = NaturalIdleRun(args)
    elif args.phone_expiry:
        from .phone_expiry import PhoneExpiryRun
        run = PhoneExpiryRun(args)
    elif args.phone_renewal == 'sustained':
        from .phone_renewal_load import PhoneRenewalLoadRun
        run = PhoneRenewalLoadRun(args)
    elif args.phone_renewal:
        from .phone_renewal import PhoneRenewalRun
        run = PhoneRenewalRun(args)
    elif args.transit:
        from .paid_phone_transit import PhoneTransitRun
        run = PhoneTransitRun(args)
    elif args.load:
        from .paid_phone_load import PhoneLoadRun
        run = PhoneLoadRun(args)
    else:
        run = PaidPhoneRun(args)
    try:
        run.execute()
    except Exception:
        (run.root / 'failure-private.txt').write_text(traceback.format_exc())
        raise
