import os
import subprocess
import time
import logging
import sys
import traceback

inboxLocation = '/nfs/data/inbox/'
outboxLocation = '/nfs/data/outbox/'
tmpLocation = '/nfs/data/tmp/'
cron_output = '/local/scramble/washing-script/log/cron-output.log'
script_log = '/nfs/data/cron-script.log'
washing_log = '/local/scramble/washing-script/log/washing-script.log'
washing_script = '/local/scramble/washing-script/washingscript.py'

def current_time():
    return time.strftime('%d-%m-%y %H:%M:%S', time.localtime())

logging.basicConfig(filename=cron_output,
                    format='%(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def main():
    try:
        if not os.path.exists(script_log):
            os.system('touch ' + script_log)
            logger.warning(current_time() + ' - cron-script.log not found. Made a new file')
        if not os.path.exists(washing_log):
            os.system('touch ' + washing_log)
            logger.warning(current_time() + ' - washing-script.log not found. Made a new file')
        if not os.path.exists(cron_output):
            os.system('touch ' + cron_output)
            logger.warning(current_time() + ' - cron-output.log not found. Made a new file')
        pythonProcess = subprocess.check_output('ps aux | grep washingscript.py', shell=True).decode()
        pythonProcess = pythonProcess.split('\n')
        content_tmp = os.listdir(tmpLocation)
        content_inbox = os.listdir(inboxLocation)
        if len(content_inbox) == 0:
            if len(content_tmp) == 0:
                if len(pythonProcess) >= 4:
                    with open(script_log, 'a') as f:
                        f.write(current_time() + ' - Script is running\n')
                    logger.info(current_time() + ' - Script is running\n')
                    sys.exit()
                if len(pythonProcess) <= 3:
                    sys.exit()

        if len(content_inbox) != 0:
            if len(pythonProcess) >= 4:
                with open(script_log, 'a') as f:
                    f.write(current_time() + ' - Script already running. Will finish before it starts on new files\n')
                logger.info(current_time() + ' - Script already running. Will finish before it starts on new files')
                sys.exit()
            if len(pythonProcess) <= 3:
                with open(script_log, 'a') as f:
                    f.write(current_time() + ' - Script starting\n')
                logger.info(current_time() + ' - Script starting\n')
                os.system('python ' + washing_script)
                logger.info(current_time() + ' - Script complete\n')

        if len(content_tmp) != 0:
            if len(pythonProcess) >= 4:
                with open(script_log, 'a') as f:
                    f.write(current_time() + ' - Script is running\n')
                logger.info(current_time() + ' - Script is running')
                sys.exit()
            if len(pythonProcess) <= 3:
                with open(script_log, 'a') as f:
                    f.write(current_time() + ' - Script will resume on tmp files\n')
                logger.info(current_time() + ' - Script will resume on tmp files\n')
                os.system('python ' + washing_script)
                logger.info(current_time() + ' - Script complete\n')
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

if __name__ == '__main__':
    main()
