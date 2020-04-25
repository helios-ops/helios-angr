import os
import importlib
import logging

l = logging.getLogger(name=__name__)

def auto_import_packages( base_module, # 'angr.procedures' 
                          base_path,   # 'angr/angr/procedures' 
                          ignore_dirs=(), 
                          ignore_files=(), 
                          scan_modules=True
                        ):
    for lib_module_name in os.listdir(base_path):
        if lib_module_name in ignore_dirs or lib_module_name == '__pycache__':
            continue

        lib_path = os.path.join(base_path, lib_module_name)
        init_path = os.path.join(lib_path, '__init__.py')

        ## 找到有 __init__.py 的文件夹，即为一个 python 包
        if not os.path.isfile(init_path):
            l.debug("Not a module: %s", lib_module_name)
            continue

        l.debug("Loading %s.%s", base_module, lib_module_name)

        try:
            package = importlib.import_module(".%s" % lib_module_name, base_module)
        except ImportError:
            l.warning("Unable to autoimport package %s.%s", base_module, lib_module_name, exc_info=True)
        else:
            if scan_modules:
                ## 这里拿到的 name, mod，是 package 目录所包含 py 文件对应的模块名称和模块实例
                for name, mod in auto_import_modules( '%s.%s' % (base_module, lib_module_name), 
                                                      lib_path,
                                                      ignore_files=ignore_files
                                                    ):

                    # dir(package): 返回 package 的属性、方法列表
                    if name not in dir(package):
                        ## 设置 package 模块对象里面的 name 名称属性值为 mod
                        setattr(package, name, mod)
            yield lib_module_name, package

def auto_import_modules( base_module,    ## package name: angr.procedures.glibc, angr.procedures.cgc, etc
                         base_path,      ## package's dirpath
                         ignore_files=()
                       ):
    ## 遍历 package dirpath 下的各个文件
    for proc_file_name in os.listdir(base_path):
        if not proc_file_name.endswith('.py'):
            continue
        if proc_file_name in ignore_files or proc_file_name == '__init__.py':
            continue

        ## 拿到 .py 前面的文件基本名。这里是指 API hook 包中的具体的函数名称
        proc_module_name = proc_file_name[:-3]

        try:
            proc_module = importlib.import_module(".%s" % proc_module_name, base_module)
        except ImportError:
            l.warning("Unable to autoimport module %s.%s", base_module, proc_module_name, exc_info=True)
            continue
        else:
            yield proc_module_name, proc_module

def filter_module(mod, type_req=None, subclass_req=None):
    for name in dir(mod):
        val = getattr(mod, name)
        if type_req is not None and not isinstance(val, type_req):
            continue
        if subclass_req is not None and not issubclass(val, subclass_req):
            continue
        yield name, val
