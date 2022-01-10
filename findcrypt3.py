# -*- coding: utf-8 -*-

import idaapi
import idautils
import ida_bytes
import ida_diskio
import idc
import operator
import yara
import os
import glob

VERSION = "0.2"
YARARULES_CFGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "findcrypt3.rules")

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET

    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

except:
    pass


p_initialized = False


class YaraSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Function", idaapi.Choose.CHCOL_PLAIN|10],
                ["Rules file", idaapi.Choose.CHCOL_PLAIN|12],
                ["Name", idaapi.Choose.CHCOL_PLAIN|25],
                ["String", idaapi.Choose.CHCOL_PLAIN|25],
                ["Value", idaapi.Choose.CHCOL_PLAIN|40],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3], res[4]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class Findcrypt_Plugin_t(idaapi.plugin_t):
    comment = "Findcrypt plugin for IDA Pro (using yara framework)"
    help = "todo"
    wanted_name = "Findcrypt"
    wanted_hotkey = "Ctrl-Alt-F"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "Findcrypt")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            self.user_directory = self.get_user_directory()
            idaapi.register_action(idaapi.action_desc_t(
                "Findcrypt",
                "Find crypto constants",
                Searcher(),
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Search", "Findcrypt", idaapi.SETMENU_APP)
            print("=" * 80)
            print("Findcrypt v{0} by David BERARD, 2017".format(VERSION))
            print("Findcrypt search shortcut key is Ctrl-Alt-F")
            print("Global rules in %s" % YARARULES_CFGFILE)
            print("User-defined rules in %s/*.rules" % self.user_directory)
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass


    def toVirtualAddress(self, offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset


    def get_user_directory(self):
        user_dir = ida_diskio.get_user_idadir()
        plug_dir = os.path.join(user_dir, "plugins")
        res_dir = os.path.join(plug_dir, "findcrypt-yara")
        if not os.path.exists(res_dir):
            os.makedirs(res_dir, 0o755)
        return res_dir


    def get_rules_files(self):
        rules_filepaths = {"global":YARARULES_CFGFILE}
        for fpath in glob.glob(os.path.join(self.user_directory, "*.rules")):
            name = os.path.basename(fpath)
            rules_filepaths.update({name:fpath})
        return rules_filepaths


    def search(self):
        memory, offsets = self._get_memory()
        rules = yara.compile(filepaths=self.get_rules_files())
        values = self.yarasearch(memory, offsets, rules)
        c = YaraSearchResultChooser("Findcrypt results", values)
        r = c.show()

    def has_user_name(ea): return (idc.get_full_flags(ea) & idc.FF_ANYNAME) == idc.FF_NAME

    def label_address(self, ea, name, predicate=None, force=False, throw=False):
        """
        Label an address with a given name or renaming the previous owner of that name.
        :param ea: address
        :param name: desired name [str, callable(address, exiting_name)]
        :param predicate: optional callback
        :param force: force name (displace existing name)
        :param throw: raise exception on error
        :return: success as bool

        label_address(ea, 'philbert', lambda x, *a: not HasUserName(x))

        `predicate` can also return an int instead of True to specify an
        alternate address, e.g.

        label_address(ea, 'philbert', lambda x, *a: idc.get_item_head(x))
        """
        def ThrowOnFailure(result):
            if not result and throw:
                raise RuntimeError("Couldn't label address {:x} with \"{}\"".format(ea, name))
            return not not result

        def MakeUniqueLabel(name, ea = BADADDR):
            fnLoc = idc.get_name_ea_simple(name)
            if fnLoc == BADADDR or fnLoc == ea:
                return name
            fmt = "%s_%%i" % name
            for i in range(1, 99999):
                tmpName = fmt % i
                fnLoc = idc.get_name_ea_simple(tmpName)
                if fnLoc == BADADDR or fnLoc == ea:
                    return tmpName
            return ""


        if ea < BADADDR:
            tmp = ea
            if callable(predicate):
                tmp  = predicate(ea, idc.get_name(ea, 0))
            if not tmp:
                return True
            # check if name already exists
            fnLoc = idc.get_name_ea_simple(name)
            if fnLoc == BADADDR:
                return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))
            elif fnLoc == ea:
                return ThrowOnFailure(True)
            else:
                if force:
                    idc.set_name(fnLoc, "", idc.SN_AUTO | idc.SN_NOWARN)
                    idc.auto_wait()
                    return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))
                else:
                    name = MakeUniqueLabel(name, ea)
                    return ThrowOnFailure(idc.set_name(ea, name, idc.SN_NOWARN))

        else:
            print("0x0%0x: Couldn't label %s, BADADDR" % (ea, name))
            return False


    def yarasearch(self, memory, offsets, rules):
        def pred(ea, name):
            head = idc.get_item_head(ea)
            if IsCode_(head):
                return head
            if IsData(head):
                return head
            if IsUnknown(head):
                return False
            return False
        print(">>> start yara search")
        values = list()
        matches = rules.match(data=memory)
        for match in matches:
            for string in match.strings:
                ea = self.toVirtualAddress(string[0], offsets)
                name = match.rule
                if name.endswith("_API"):
                    try:
                        name = name + "_" + idc.GetString(ea)
                    except:
                        pass
                value = [
                    ea,
                    GetFuncName(ea),
                    match.namespace,
                    name + "_" + hex(ea).lstrip("0x").rstrip("L").upper(),
                    string[1],
                    repr(string[2]),
                ]
                label = name + "_" + hex(ea).lstrip("0x").rstrip("L").upper()
                self.label_address(value[0], label, predicate=pred)
                values.append(value)
        print("<<< end yara search")
        return values

    def _get_memory(self):
        result = bytearray()
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_attr(start, idc.SEGATTR_END)
            result += ida_bytes.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return bytes(result), offsets

    def run(self, arg):
        self.search()


# register IDA plugin
def PLUGIN_ENTRY():
    return Findcrypt_Plugin_t()

_load_method = None
if __name__ == "__main__":
    # loaded directly
    _load_method = 'direct'
elif __name__.startswith("__plugins__"):
    _load_method = 'plugin'
    # loaded as a plugin
elif __name__ == "findcrypt3":
    _load_method = 'module'
else:
    # unknown load method (filename could be changed?)
    _load_method = 'unknown'
    print("[findcrypt3]: unknown load method '{}'".format(__name__))

if _load_method == 'direct':
    fcp = Findcrypt_Plugin_t()
    fcp.init()
    fcp.run(0)
