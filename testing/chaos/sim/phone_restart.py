"""One recorded Android package force-stop; never clear data or repeat dispatch."""
import re
import shlex

from .phone_customer import save
from .paid_settlement import require


def process(phone):
    # pidof uses exit 1 for absence; missing tools and other failures stay errors.
    command = 'pidof ' + shlex.quote(phone.package) + '; code=$?; test "$code" -le 1'
    pid = phone.shell('sh', '-c', command).decode().strip()
    if not pid:
        return None
    require(re.fullmatch(r'[1-9][0-9]*', pid) is not None, 'expected one exact app process')
    argv = phone.shell('run-as', phone.package, 'cat', '/proc/' + pid + '/cmdline')
    require(argv.rstrip(b'\0').decode() == phone.package, 'app process name differs')
    stat = phone.shell('run-as', phone.package, 'cat', '/proc/' + pid + '/stat').decode()
    start = int(stat.rsplit(') ', 1)[1].split()[19])
    return {'pid': int(pid), 'start_ticks': start, 'package': phone.package}


def force_stop(phone):
    """Android force-stop kills the candidate without its Settle/Stop UI actions."""
    with phone.locked():
        phone.ensure_ready()
        phone.check()
        state = phone.status()['customer']
        require(state['configured'] and state['running'], 'candidate account is not running')
        before = process(phone)
        require(before is not None, 'candidate has no live process to interrupt')
        save(phone.root / 'process-stop-intent.json', before)
        phone.shell('am', 'force-stop', phone.package)
        require(process(phone) is None, 'candidate process remains after force-stop')
        result = {'before': before, 'absent_after_stop': True}
        save(phone.root / 'process-stop-result.json', result)
        return result
