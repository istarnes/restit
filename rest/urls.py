from django.conf.urls import *
from django.conf import settings
from django.urls import path, include
import django

from . import views
import pkgutil
import importlib
import sys
import version
import time
from datetime import datetime
import platform
import subprocess
from . import joke
from . import helpers
import traceback


try:
    import psutil
except Exception:
    print("no psutil")

SOFTWARE_VERSIONS = getattr(settings, 'SOFTWARE_VERSIONS', None)
# SOFTWARE_VERSIONS_ACTUAL = {}


def safe_cmd(cmd, *args):
    try:
        cmd_args = [cmd]
        if len(args):
            cmd_args.extend(list(args))
        return helpers.toString(subprocess.check_output(cmd_args, shell=True).strip())
    except Exception as err:
        return str(err)
        # print( str(err))
    return None


def getVersions():
    out = {}
    for key in SOFTWARE_VERSIONS:
        if key == "django":
            out[key] = django.__version__
        else:
            out[key] = safe_cmd(SOFTWARE_VERSIONS[key])
    return out


def getBlockedHosts():
    blocked = []
    with open("/etc/hosts.deny", 'r') as f:
        for line in f.readlines():
            if line.startswith("#"):
                continue
            blocked.append(line.strip())
    return blocked


def getSystemInfo(request):
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()

    out = {
        "time": time.time(),
        "datetime": str(datetime.now()),
        "version": version.VERSION,
        "os": {
            "system": platform.system(),
            "version": platform.version(),
            "hostname": platform.node(),
            "release": platform.release(),
            "processor": platform.processor(),
            "machine": platform.machine()
        },
        "cpu": {
            "count": psutil.cpu_count(),
            "freq": psutil.cpu_freq(),
        },
        "boot_time": psutil.boot_time(),
        "cpu_load": psutil.cpu_percent(),
        "cpus_load": psutil.cpu_percent(percpu=True),
        "memory": {
            "total": mem.total,
            "used": mem.used,
            "available": mem.available,
            "percent": mem.percent
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        },
        "network": {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
            "errin": net.errin,
            "errout": net.errout,
            "dropin": net.dropin,
            "dropout": net.dropout
        },
        "users": psutil.users()
    }
    if request.DATA.get("versions") and SOFTWARE_VERSIONS:
        out["versions"] = getVersions()
    if request.DATA.get("blocked"):
        out["blocked"] = getBlockedHosts()
    return views.restGet(request, out)


def getJoke(request):
    return views.restGet(request, {"joke": joke.getRandomJoke()})


def webhook(request):
    return "ok"


def loadModule(mod):
    if pkgutil.find_loader(mod) is not None:
        return importlib.import_module(mod)
    return None


def getVersion(request):
    return views.restStatus(request, True, {"data": version.VERSION})


urlpatterns = [
    url(r'^system/info$', getSystemInfo),
    url(r'^webhook$', webhook),
    url(r'^version$', getVersion),
    url(r'^docs$', views.showDocs),
    url(r'^upload$', views.chunkUploadView),
    url(r'^joke$', getJoke),
]


def load_app(app, root_module=None):
    module = None
    try:
        module = loadModule(app + '.rpc')
    except ImportError as err:
        print("**** failed to load {0}.rpc! ****".format(app))
        print("**** missing dependencies ****")
        print("**** {0} ****".format(err))
    except SyntaxError:
        print("\t{0}: fail".format(app))
        print("Exception in user code:")
        print('-' * 60)
        traceback.print_exc(file=sys.stdout)
        print('-' * 60)
    except Exception:
        print("\t{0}: fail".format(app))
        print("Exception in user code:")
        print('-' * 60)
        traceback.print_exc(file=sys.stdout)
        print('-' * 60)
    if module:
        if not root_module:
            root_module = module
        # print(module.__name__)
        # urls = URLResolver('^' + getattr(module, 'URL_PREFIX', app.split('.')[-1]) + "/", root_module)
        urls = path(getattr(module, 'URL_PREFIX', app.split('.')[-1]) + "/", include(root_module))
        # print(urls.url_patterns)
        # print("")
        urlpatterns.append(urls)
    return module


for app in settings.INSTALLED_APPS:
    module = load_app(app)
    if module:
        if hasattr(module, "RPC_MODULES"):
            print("HAS RPC_MODULES")
            sub_modules = getattr(module, "RPC_MODULES")
            print(sub_modules)

            for m in sub_modules:
                load_app(m, module)





