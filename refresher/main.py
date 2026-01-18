from scheduler import Scheduler
from smb import watch


def main():
    scheduler = Scheduler()
    watch(lambda dir, action: scheduler.add_scan(dir, action))


if __name__ == "__main__":
    main()
