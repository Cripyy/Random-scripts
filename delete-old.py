import os
import subprocess
import time
import logging
import traceback
import sys

log_folder = '/local/scramble/washing-script/log/'
outboxLocation = '/nfs/data/outbox/'
cron_log = '/nfs/data/cron-script.log'
cron_output = '/local/scramble/washing-script/log/cron-output.log'

def current_time():
    return time.strftime('%d-%m-%y %H:%M:%S', time.localtime())

logging.basicConfig(filename=cron_output,
                    format='%(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def d_format():
    return time.strftime('%d-%m', time.localtime())

def remove_old_files():
    try:
        remove_files = subprocess.check_output('find ' + outboxLocation + ' -maxdepth 1 -type d -mtime +30',
                                               shell=True).decode()
        remove_files = remove_files.split('\n')
        if len(remove_files) > 1:
            with open(cron_log, 'a') as f:
                f.write(current_time() + ' - The following files are over 30 days old and will be deleted:\n')
            logger.info(current_time() + ' - The following files are over 30 days old and will be deleted:\n')
            for i in remove_files:
                with open(cron_log, 'a') as f:
                    f.write(i + '\n')
                logger.info(i + '\n')
            os.system('find ' + outboxLocation + ' -maxdepth 1 -type d -mtime +30 -exec rm -r "{}" \;')
        script_rotate()
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def script_rotate():
    try:
        script_log = 'washing-script.log'
        os.chdir(log_folder)
        pythonProcess = subprocess.check_output('ps aux | grep washingscript.py', shell=True).decode()
        pythonProcess = pythonProcess.split('\n')
        if len(pythonProcess) <= 3:
            if os.path.getsize(script_log) >= 20 * 20 * 1024:
                logger.info(current_time() + ' - Rotating washing-script.log file (old log: ' + script_log + '.' +
                      str(d_format()) + '.gz)')
                os.system('gzip -c ' + script_log + ' > ' + script_log + '.' + str(d_format()) + '.gz')
                os.system('rm ' + script_log + ' && touch ' + script_log)
            if os.path.getsize(script_log) <= 20 * 20 * 1024:
                logger.info(current_time() + ' - washing-script.log does not exceed 20MB, will not rotate')
        if len(pythonProcess) >= 4:
            if os.path.getsize(script_log) >= 20 * 20 * 1024:
                logger.error(current_time() + ' - Washing-script is running, will not rotate washing-script.log')
            if os.path.getsize(script_log) <= 20 * 20 * 1024:
                logger.info(current_time() + ' - washing-script.log does not exceed 20MB, will not rotate')

        delete_old_log = subprocess.check_output('find ' + log_folder + ' -name "*.gz" -mtime +30', shell=True).decode()
        delete_old_log = delete_old_log.split('\n')
        if len(delete_old_log) > 1:
            os.system('find ' + log_folder + ' -name "*.gz" -mtime +30 -exec rm -r "{}" \;')
        cron_rotate()
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def cron_rotate():
    try:
        cron_name = 'cron-script.log'
        if os.path.getsize(cron_log) >= 20 * 20 * 1024:
            logger.info(current_time() + ' - Rotating cron-script.log file (old log: ' + cron_name + '.' +
                        str(d_format()) + '.gz)')
            os.system('gzip -c ' + cron_log + ' > ' + cron_name + '.' + str(d_format()) + '.gz')
            os.system('rm ' + cron_log + ' && touch ' + cron_log)
        if os.path.getsize(cron_log) <= 20 * 20 * 1024:
            logger.info(current_time() + ' - cron-script.log does not exceed 20MB, will not rotate')
        cron_output_rotate()
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

def cron_output_rotate():
    try:
        cron_output_name = 'cron-output.log'
        if os.path.getsize(cron_output) >= 20 * 20 * 1024:
            logger.info(current_time() + ' - Rotating cron-script.log file (old log: ' + cron_output_name + '.' +
                        str(d_format()) + '.gz)')
            os.system('gzip -c ' + cron_output + ' > ' + cron_output_name + '.' + str(d_format()) + '.gz')
            os.system('rm ' + cron_output + ' && touch ' + cron_output)
        if os.path.getsize(cron_output) <= 20 * 20 * 1024:
            logger.info(current_time() + ' - cron-output.log does not exceed 20MB, will not rotate')
    except Exception:
        logger.error(current_time() + ' - An error occurred:\n' + traceback.format_exc())

if __name__ == '__main__':
    remove_old_files()
