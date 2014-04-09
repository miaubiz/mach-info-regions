#!/usr/bin/python
# coding: utf-8

import commands
import platform
import os
import re
import sys
import optparse
import shlex
from funcy import re_find, compact

try:
    # Just try for LLDB in case PYTHONPATH is already correctly setup
    import lldb
except ImportError:
    lldb_python_dirs = list()
    # lldb is not in the PYTHONPATH, try some defaults for the current platform
    platform_system = platform.system()
    if platform_system == 'Darwin':
        # On Darwin, try the currently selected Xcode directory
        xcode_dir = commands.getoutput("xcode-select --print-path")
        if xcode_dir:
            lldb_python_dirs.append(os.path.realpath(xcode_dir + '/../SharedFrameworks/LLDB.framework/Resources/Python'))
            lldb_python_dirs.append(xcode_dir + '/Library/PrivateFrameworks/LLDB.framework/Resources/Python')
        lldb_python_dirs.append('/System/Library/PrivateFrameworks/LLDB.framework/Resources/Python')
    success = False
    for lldb_python_dir in lldb_python_dirs:
        if os.path.exists(lldb_python_dir):
            if not (sys.path.__contains__(lldb_python_dir)):
                sys.path.append(lldb_python_dir)
                try:
                    import lldb
                except ImportError:
                    pass
                else:
                    print 'imported lldb from: "%s"' % (lldb_python_dir)
                    success = True
                    break
    if not success:
        print "error: couldn't locate the 'lldb' module, please set PYTHONPATH correctly"
        sys.exit(1)


def create_xx_options(name):
    parser = optparse.OptionParser(prog=name)
    return parser


def mama_parser(parser):
  parser.usage = "mama [pointer]"


def mama_command(debugger, command, result, dict):
  xx_command(debugger, command, result, dict, mama_wrap, mama_parser)


def xx_command(debugger, command, result, dict, delegate_to, extra_options=None):
    # Use the Shell Lexer to properly parse up command options just like a
    # shell would
    command_args = shlex.split(command)
    parser = create_xx_options(delegate_to.__name__)
    if extra_options:
      extra_options(parser)
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        # if you don't handle exceptions, passing an incorrect argument to the OptionParser will cause LLDB to exit
        # (courtesy of OptParse dealing with argument errors by throwing SystemExit)
        result.SetStatus(lldb.eReturnStatusFailed)
        print >>result, "error: option parsing failed"  # returning a string is the same as returning an error whose description is the string
        return
    delegate_to(debugger.GetSelectedTarget(), options, args, result)


def prot_string(i):
  VM_PROT_READ = 0x01
  VM_PROT_WRITE = 0x02
  VM_PROT_EXECUTE = 0x04
  r = "r" if i & VM_PROT_READ else "-"
  w = "w" if i & VM_PROT_WRITE else "-"
  x = "x" if i & VM_PROT_EXECUTE else "-"
  return "".join([r, w, x])


def zone_expr():
  return '''
struct zone_info {
  uintptr_t *zone;
  const char *zone_name;
};
#define NUMBER_OF_ZONES %#x
zone_info infos[NUMBER_OF_ZONES];
uintptr_t ptrs[NUMBER_OF_ZONES];
%s
for (int i=0; i<NUMBER_OF_ZONES; i++) {
  infos[i].zone = (uintptr_t*) malloc_zone_from_ptr(ptrs[i]);
  infos[i].zone_name = "???";
  if (infos[i].zone) {
    infos[i].zone_name = (const char*) malloc_get_zone_name(infos[i].zone);
  }
}
infos
'''


def trgt():
  target_string = lldb.debugger.GetTargetAtIndex(0).triple
  SHARED_REGION_BASE_X86_64 = 0x00007FFF70000000
  SHARED_REGION_BASE_ARM = 0xffffffffffffffff
  archs = {
      'x86_64-apple-macosx': {'shared_region_base': SHARED_REGION_BASE_X86_64, 'extra': osx_vm_region_extended_info},
      #'i386-apple-macosx': {'shared_region_base': SHARED_REGION_BASE_X86_64, 'extra': osx_vm_region_extended_info}, # doesn't work. lol.
      'arm64-apple-ios': {'shared_region_base': SHARED_REGION_BASE_ARM, 'extra': ios_vm_region_extended_info},
      'arm-apple-ios': {'shared_region_base': SHARED_REGION_BASE_ARM, 'extra': ios_vm_region_extended_info}
        }
  return archs[target_string]


def thread_for_stack(start, end):
  process = lldb.debugger.GetSelectedTarget().GetProcess()
  for thread in process:
    if start <= thread.frame[0].sp and end >= thread.frame[0].sp:
      descriptions = [str(thread.GetIndexID()), thread.GetQueueName(), thread.GetName()]
      return " thread %s" % " ".join(compact(descriptions))
  return ""


def zone(ptrs):
  frame = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
  expr_options = lldb.SBExpressionOptions()
  expr_options.SetIgnoreBreakpoints(True)
  expr_options.SetFetchDynamicValue(lldb.eNoDynamicValues)
  expr_options.SetTimeoutInMicroSeconds(30 * 1000 * 1000)  # 30 second timeout
  expr_options.SetTryAllThreads(False)
  ptrzz = []
  for i, ptr in enumerate(ptrs):
    ptrzz.append("ptrs[%#x] = %s;" % (i, ptr))

  exprz = zone_expr() % (len(ptrs), "\n".join(ptrzz))
  expr_sbvalue = frame.EvaluateExpression(exprz, expr_options)
  if expr_sbvalue.error.Success():
    result = {}
    for i, ptr in enumerate(ptrs):
      rz = expr_sbvalue.GetChildAtIndex(i)
      zone_name = rz.GetValueForExpressionPath(".zone_name").GetSummary()
      if zone_name:
        zone_name = zone_name[1:-1]
      else:
        zone_name = "null??"
      _zone = rz.GetValueForExpressionPath(".zone").GetValueAsUnsigned()
      result[ptr] = "%s_%#x" % (zone_name, _zone)
    return result
  else:
    print "failure, %s" % expr_sbvalue.error


def in_region(ptr, start, size):
  return ptr >= start and ptr < (start + size)


def mama_wrap(target, options, args, result):
  result = mama(target, options, args, result)
  for (start, size, line) in result:
    print line


def mama(target, options, args, result):
  ret = []
  needle = None
  if len(args):
    needle = exp(" ".join(args))
  arch = trgt()
  expr_options = lldb.SBExpressionOptions()
  expr_options.SetIgnoreBreakpoints(True)
  expr_options.SetFetchDynamicValue(lldb.eNoDynamicValues)
  expr_options.SetTimeoutInMicroSeconds(30 * 1000 * 1000)  # 30 second timeout
  expr_options.SetTryAllThreads(False)
  max_results = 0x1000
  frame = lldb.debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame()
  expr_sbvalue = frame.EvaluateExpression(mach_vm_region_expr() % (arch['extra'](), max_results), expr_options)
  if expr_sbvalue.error.Success():
    result_value = lldb.value(expr_sbvalue)
    starts = []
    malloc_tags = [1, 2, 3, 4, 6, 7, 8, 9, 11, 53, 61]
    for i in range(max_results):
      region_lol = result_value[i]
      start = int(region_lol.addr)
      size = int(region_lol.size)
      user_tag_int = int(region_lol.info.user_tag)
      if user_tag_int in malloc_tags and (not needle or in_region(needle, start, size)):
        starts.append(start)
    _zones = {}
    if len(starts):
      _zones = zone(starts)

    reached_the_end = False
    for i in range(max_results):
      region_lol = result_value[i]
      size = int(region_lol.size)
      start = int(region_lol.addr)
      if start >= arch['shared_region_base']:
        reached_the_end = True
      end = start + size
      info = region_lol.info
      prot = int(info.protection)
      user_tag_int = int(info.user_tag)
      # from /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.8.sdk/System/Library/Frameworks/Kernel.framework/Headers/mach/vm_statistics.h
      # I only put in the ones I ran into
      user_tagz = {
          0: "unknown",
          1: "malloc",
          2: "malloc small",
          3: "malloc large",
          4: "malloc huge",
          # 5: "sbrk",
          6: "realloc",
          7: "malloc tiny",
          8: "malloc large reusable",
          9: "malloc large reused",
          10: "memory analysis tool",
          11: "malloc nano",
          20: "mach msg",
          21: "iokit",
          30: "stack",
          31: "guard",
          32: "shared pmap",
          33: "dylib",
          34: "objc dispatchers",
          35: "unshared pmap",
          40: "appkit",
          41: "foundation",
          42: "core graphics",
          43: "core services",
          44: "java",
          45: "coredata",
          46: "coredata objectids",
          50: "ats",
          51: "layerkit",
          52: "cgimage",
          53: "tcmalloc",
          54: "coregraphics data",
          55: "coregraphics shared",
          56: "coregraphics framebuffers",
          57: "coregraphics backingstores",
          60: "dyld",
          61: "dyld mallco",
          62: "sqlite",
          63: "javascript core heap",
          64: "javascript JIT executable allocator",
          65: "javascript JIT register file",
          66: "GLSL",
          67: "OpenCL",
          68: "core image",
          69: "webcore purgeable buffers",
          70: "imageio",
          71: "coreprofile",
          72: "assetsd / MobileSlideShow",
          73: "kernel alloc once",
          74: "libdispatch",
          75: "accelerate",
          76: "coreui",
          242: "application specific 242",
          251: "application specific 251"
               }
      user_tag = user_tagz.get(user_tag_int)
      if user_tag_int == 30:
        user_tag = "".join([user_tag, thread_for_stack(start, end)])
      if not user_tag:
        print "USER TAG NOT FOUDN: %s" % user_tag_int
      ref_count = int(info.ref_count)
      object_name = int(region_lol.object_name)
      if object_name != 0:
        print "YEHAHA %#x" % object_name
      share_mode = int(info.share_mode)
      share_modez = ['????', 'COW', 'PRV', 'NUL', 'ALI', 'SHM', 'ZER', 'S/A', 'large page']
      share_mode = share_modez[share_mode]
      if start < arch['shared_region_base']:
        lookup_output = run_command("target modules lookup -v -a %#x" % start, True)
      elif needle:
        lookup_output = run_command("target modules lookup -v -a %#x" % needle, True)
      filename = ""
      section = ""
      if lookup_output:
        if user_tag_int != 0 and user_tag_int != 33 and user_tag_int != 35 and user_tag_int != 32:
          print "oh shit! %d" % user_tag_int
          break
        filename = re_find(r"file = \"([^\"]*)", lookup_output)
        filename = re.sub(r".*/SDKs", "...", filename)
        filename = re.sub(r".*/iOS DeviceSupport", "...", filename)
        section = re_find(r"__[\w]*", lookup_output)
        if section and filename and user_tag_int == 0:
          user_tag = ""
      else:
        if user_tag_int == 33:
          print "noh shit! %#x" % user_tag_int
          break
      maybe_guard = "guard" if prot == 0 and user_tag_int == 30 else ""
      maybe_unallocated = "" if ref_count else "(zero refcount)"
      maybes = [maybe_guard, maybe_unallocated][not maybe_guard]
      if size == 0xe800000 and user_tag_int == 32 and ref_count == 0:
        reached_the_end = True
      else:
        if not needle or in_region(needle, start, size):
          _zone = _zones[start] if user_tag_int in malloc_tags else ""
          ret.append((start, size, "{:#x} - {:#x} - {:<5s} - {:} SM={:} {:}".format(start, end, human(size), prot_string(prot), share_mode, " ".join(compact([section, user_tag, maybes, filename, _zone])))))
      if share_mode == "NUL" and ref_count == 0 and prot == 5:
        break
    if not reached_the_end:
      print "didn't reach the end?"
    return ret
  else:
      print "failure, %s" % expr_sbvalue.error


def run_command(command, silent=False):
      return_obj = lldb.SBCommandReturnObject()
      lldb.debugger.GetCommandInterpreter().HandleCommand(command, return_obj)
      if return_obj.Succeeded():
        return return_obj.GetOutput()
      else:
        if not silent:
          print return_obj
          print "GIANT ERROR!"
          raise ValueError


def exp(e):
  o = run_command('expr -fx -- %s' % e)
  h = re_find(r"0x[0-9a-f]*", o)
  return int(h, 0)


def human(size):
  for x in ['b', 'k', 'm', 'g']:
    if size < 1024:
      return "%d%s" % (size, x)
    size /= 1024


# from /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS7.0.sdk/usr/include/mach/vm_region.h
def ios_vm_region_extended_info():
  return '''
#define VM_REGION_EXTENDED_INFO	11
struct vm_region_extended_info {
  vm_prot_t		protection;
        unsigned int            user_tag;
        unsigned int            pages_resident;
        unsigned int            pages_shared_now_private;
        unsigned int            pages_swapped_out;
        unsigned int            pages_dirtied;
        unsigned int            ref_count;
        unsigned short          shadow_depth;
        unsigned char           external_pager;
        unsigned char           share_mode;
  unsigned int		pages_reusable;
};

typedef struct vm_region_extended_info		*vm_region_extended_info_t;
typedef struct vm_region_extended_info		 vm_region_extended_info_data_t;

#define VM_REGION_EXTENDED_INFO_V1_SIZE		(sizeof (vm_region_extended_info_data_t))
#define VM_REGION_EXTENDED_INFO_V0_SIZE		(VM_REGION_EXTENDED_INFO_V1_SIZE - sizeof (unsigned int) /* pages_reusable */)

#define VM_REGION_EXTENDED_INFO_V1_COUNT	((mach_msg_type_number_t)(VM_REGION_EXTENDED_INFO_V1_SIZE / sizeof (int)))
#define VM_REGION_EXTENDED_INFO_V0_COUNT	((mach_msg_type_number_t)(VM_REGION_EXTENDED_INFO_V0_SIZE / sizeof (int)))

#define VM_REGION_EXTENDED_INFO_COUNT		VM_REGION_EXTENDED_INFO_V1_COUNT
'''


# from /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.9.sdk/usr/include/mach/vm_region.h
def osx_vm_region_extended_info():
  return '''
#define VM_REGION_EXTENDED_INFO	13
struct vm_region_extended_info {
        vm_prot_t		protection;
        unsigned int            user_tag;
        unsigned int            pages_resident;
        unsigned int            pages_shared_now_private;
        unsigned int            pages_swapped_out;
        unsigned int            pages_dirtied;
        unsigned int            ref_count;
        unsigned short          shadow_depth;
        unsigned char           external_pager;
        unsigned char           share_mode;
        unsigned int            pages_reusable;
};
typedef struct vm_region_extended_info		*vm_region_extended_info_t;
typedef struct vm_region_extended_info		vm_region_extended_info_data_t;
#define VM_REGION_EXTENDED_INFO_COUNT			\
  ((mach_msg_type_number_t)			\
  (sizeof (vm_region_extended_info_data_t) / sizeof (natural_t)))
'''


def mach_vm_region_expr():
  return '''
#define KERN_SUCCESS 0
typedef int   kern_return_t;
typedef int vm_prot_t;
typedef unsigned int    natural_t;
typedef unsigned int    vm_inherit_t; /* might want to change this */
typedef unsigned long long  memory_object_offset_t;
typedef unsigned int  boolean_t;
typedef uint32_t vm32_object_id_t;
typedef unsigned int mach_port_t;
typedef mach_port_t   vm_map_t;
typedef int   vm_behavior_t;
typedef natural_t mach_msg_type_number_t;
typedef uintptr_t   vm_offset_t;
typedef vm_offset_t       vm_address_t;

typedef uintptr_t   vm_size_t;

%s

mach_port_t task = (mach_port_t)mach_task_self();
vm_address_t vm_region_base_addr;
vm_size_t vm_region_size;
natural_t vm_region_depth;
vm_region_extended_info_data_t vm_region_info;
kern_return_t err;

mach_port_t object_name;
struct $region_lol {
  void *addr;
  vm_size_t size;
  vm_region_extended_info_data_t info;
  mach_port_t object_name;
};
#define NUM_MATCHES %#x
$region_lol matches[NUM_MATCHES];
vm_region_base_addr = 1;
mach_msg_type_number_t vm_region_info_size = VM_REGION_EXTENDED_INFO_COUNT;
for (int jj=0; jj<NUM_MATCHES; jj++) {
kern_return_t kret = (kern_return_t) mach_vm_region(task, &vm_region_base_addr, &vm_region_size, VM_REGION_EXTENDED_INFO, &vm_region_info, &vm_region_info_size, &object_name);
matches[jj].addr = (void*)vm_region_base_addr;
matches[jj].size = vm_region_size;
matches[jj].object_name = object_name;
matches[jj].info.protection = vm_region_info.protection;
matches[jj].info.share_mode = vm_region_info.share_mode;
matches[jj].info.user_tag = vm_region_info.user_tag;
matches[jj].info.ref_count = vm_region_info.ref_count;
vm_region_base_addr += vm_region_size;
}
matches
'''

if __name__ == '__main__':
    print 'error: this script is designed to be used within the embedded script interpreter in LLDB'
elif getattr(lldb, 'debugger', None):
    lldb.debugger.HandleCommand('command script add -f %s.mama_command mama' % __name__)
    print 'vmmap command "mama" added'
