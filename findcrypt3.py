# -*- coding: utf-8 -*-

import idaapi
import idautils
import idc
import operator
import yara
import os

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
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            return idaapi.AST_DISABLE_FOR_FORM

    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

except:
    pass

def lrange(num1, num2=None, step=1):
    op = operator.__lt__
    if num2 is None:
        num1, num2 = 0, num1
    if num2 < num1:
        if step > 0:
            num1 = num2
        op = operator.__gt__
    elif step < 0:
        num1 = num2
    while op(num1, num2):
        yield num1
        num1 += step

p_initialized = False



class YaraSearchResultChooser(idaapi.Choose2):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose2.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose2.CHCOL_HEX|10],
                ["Name", idaapi.Choose2.CHCOL_PLAIN|25],
                ["String", idaapi.Choose2.CHCOL_PLAIN|25],
                ["Value", idaapi.Choose2.CHCOL_PLAIN|40],
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
        idc.Jump(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3]]
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
            idaapi.register_action(idaapi.action_desc_t(
                "Findcrypt",
                "Find crypto constants",
                self.search,
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Edit/Findcrypt", "Findcrypt", idaapi.SETMENU_APP)
            print("=" * 80)
            print("Findcrypt v{0} by David BERARD, 2017".format(VERSION))
            print("Findcrypt search shortcut key is Ctrl-Alt-F")
            print("Rules in %s" % YARARULES_CFGFILE)
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

    def search(self):
        memory, offsets = self._get_memory()
        rules = yara.compile(YARARULES_CFGFILE)
        values = self.yarasearch(memory, offsets, rules)
        c = YaraSearchResultChooser("Findcrypt results", values)
        r = c.show()

    def yarasearch(self, memory, offsets, rules):
        print ">>> start yara search"
        values = list()
        matches = rules.match(data=memory)
        for match in matches:
            #print "%s => %d matches" % (name, len(match.strings))
            for string in match.strings:
                # print "\t 0x%08x : %s" % (self.toVirtualAddress(string[0],offsets),repr(string[2]))
                name = match.rule
                if name.endswith("_API"):
                    try:
                        name = name + "_" + idc.GetString(self.toVirtualAddress(string[0], offsets))
                    except:
                        pass
                value = [
                    self.toVirtualAddress(string[0], offsets),
                    name + "_" + hex(self.toVirtualAddress(string[0], offsets)).lstrip("0x").rstrip("L").upper(),
                    string[1],
                    repr(string[2]),
                ]
                idaapi.set_name(value[0], name
                             + "_"
                             + hex(self.toVirtualAddress(string[0], offsets)).lstrip("0x").rstrip("L").upper()
                             , 0)
                values.append(value)
        print "<<< end yara search"
        return values

    def _get_memory(self):
        result = ""
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.SegEnd(start)
            for ea in lrange(start, end):
                result += chr(idc.Byte(ea))
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return result, offsets

    def run(self, arg):
        self.search()


# register IDA plugin
def PLUGIN_ENTRY():
    return Findcrypt_Plugin_t()
