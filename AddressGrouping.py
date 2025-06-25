import ida_idaapi
import ida_kernwin
import ida_netnode
import ida_nalt
import idc
import pickle
import idaapi
from PyQt5 import QtWidgets, QtCore, QtGui

title = "AddressGrouping"

def qt_select_group(groups):
    class GroupSelectDialog(QtWidgets.QDialog):
        def __init__(self, groups, parent=None):
            super().__init__(parent)
            self.setWindowTitle("选择分组")
            self.setModal(True)
            self.selected = None
            layout = QtWidgets.QVBoxLayout(self)
            self.list = QtWidgets.QListWidget(self)
            self.list.addItems(groups)
            layout.addWidget(self.list)
            btns = QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
            self.buttonBox = QtWidgets.QDialogButtonBox(btns)
            layout.addWidget(self.buttonBox)
            self.buttonBox.accepted.connect(self.accept)
            self.buttonBox.rejected.connect(self.reject)
            self.list.itemDoubleClicked.connect(self.accept)
        def accept(self):
            item = self.list.currentItem()
            if item:
                self.selected = item.text()
            super().accept()
    # 获取IDA主窗口作为父窗口
    try:
        import sip
        import ida_kernwin
        mainwin = ida_kernwin.get_current_widget()
        parent = sip.wrapinstance(int(mainwin), QtWidgets.QWidget)
    except Exception:
        parent = None
    dlg = GroupSelectDialog(groups, parent)
    if dlg.exec_() == QtWidgets.QDialog.Accepted and dlg.selected:
        return dlg.selected
    return None

def select_group(groups):
    if not groups:
        return None
    if len(groups) == 1:
        return groups[0]
    # 优先用Qt弹窗
    return qt_select_group(groups)

# 多级树结构节点
def make_node(name, is_addr=False, comment="", color=None):
    return {"name": name, "is_addr": is_addr, "children": [], "comment": comment, "color": color}

class BookmarkManager:
    def __init__(self):
        self.netnode = ida_netnode.netnode()
        self.netnode.create("$ CustomBookmarks")
        self.imagebase = ida_nalt.get_imagebase()
        self.load()
        self._refresh_callback = None

    def set_refresh_callback(self, cb):
        self._refresh_callback = cb

    def _refresh(self):
        if self._refresh_callback:
            self._refresh_callback()

    def save(self):
        blob = pickle.dumps(self.bookmarks)
        self.netnode.setblob(blob, 0, 'C')
        self._refresh()

    def load(self):
        blob = self.netnode.getblob(0, 'C')
        if blob is not None:
            data = pickle.loads(blob)
            # 自动升级老格式
            if isinstance(data, dict):
                # 老格式：{group: [offset, ...]}
                new_bookmarks = []
                for group, addrs in data.items():
                    node = make_node(group, is_addr=False)
                    for offset in addrs:
                        node["children"].append(make_node(hex(offset + self.imagebase), is_addr=True))
                    new_bookmarks.append(node)
                self.bookmarks = new_bookmarks
                self.save()  # 升级后立即保存为新格式
            else:
                self.bookmarks = data
        else:
            self.bookmarks = []

    def add_group(self, group):
        group = str(group).strip()
        if group and not any(n["name"] == group for n in self.bookmarks):
            self.bookmarks.append(make_node(group, is_addr=False))
            self.save()
            ida_kernwin.msg(f"[AddressGrouping] 已添加分组: {group}\n")

    def del_group(self, group):
        group = str(group).strip()
        before = len(self.bookmarks)
        self.bookmarks = [n for n in self.bookmarks if n["name"] != group]
        if len(self.bookmarks) != before:
            self.save()
            ida_kernwin.msg(f"[AddressGrouping] 已删除分组: {group}\n")

    def add_child(self, parent_path, name, is_addr=False, comment="", color=None):
        node = self.find_node_by_path(parent_path)
        if node is not None:
            if not any(c["name"] == name for c in node["children"]):
                node["children"].append(make_node(name, is_addr, comment, color))
                self.save()
                ida_kernwin.msg(f"[AddressGrouping] 已添加子节点: {name} 到 {'/'.join(parent_path)}\n")

    def del_child(self, parent_path, name):
        node = self.find_node_by_path(parent_path)
        if node is not None:
            before = len(node["children"])
            node["children"] = [c for c in node["children"] if c["name"] != name]
            if len(node["children"]) != before:
                self.save()
                ida_kernwin.msg(f"[AddressGrouping] 已删除子节点: {name} 从 {'/'.join(parent_path)}\n")

    def find_node_by_path(self, path):
        nodes = self.bookmarks
        node = None
        for name in path:
            node = next((n for n in nodes if n["name"] == name), None)
            if node is None:
                return None
            nodes = node["children"]
        return node

    def get_groups(self):
        return [n["name"] for n in self.bookmarks]

    def add_addr(self, group, ea):
        group = str(group).strip()
        node = next((n for n in self.bookmarks if n["name"] == group), None)
        if node is None:
            ida_kernwin.msg(f"[AddressGrouping] 分组 {group} 不存在，无法添加地址！\n")
            return False
        addr_str = hex(ea)
        if not any(c["name"] == addr_str and c["is_addr"] for c in node["children"]):
            node["children"].append(make_node(addr_str, is_addr=True))
            self.save()
            ida_kernwin.msg(f"[AddressGrouping] 地址 {addr_str} 已添加到分组 {group}\n")
            return True
        else:
            ida_kernwin.msg(f"[AddressGrouping] 地址 {addr_str} 已经存在于分组 {group}\n")
            return False

    def del_addr(self, group, ea):
        group = str(group).strip()
        node = next((n for n in self.bookmarks if n["name"] == group), None)
        if node is not None:
            addr_str = hex(ea)
            before = len(node["children"])
            node["children"] = [c for c in node["children"] if not (c["name"] == addr_str and c["is_addr"])]
            if len(node["children"]) != before:
                self.save()
                ida_kernwin.msg(f"[AddressGrouping] 地址 {addr_str} 已从分组 {group} 删除\n")

    def set_comment(self, path, comment):
        node = self.find_node_by_path(path)
        if node is not None:
            node["comment"] = comment
            self.save()
            ida_kernwin.msg(f"[AddressGrouping] 已设置备注: {comment} -> {'/'.join(path)}\n")

    def set_color(self, path, color):
        node = self.find_node_by_path(path)
        if node is not None:
            node["color"] = color
            self.save()
            ida_kernwin.msg(f"[AddressGrouping] 已设置颜色: {color} -> {'/'.join(path)}\n")

    def clear_all_colors(self):
        def clear_node_color(node):
            node["color"] = None
            for child in node["children"]:
                clear_node_color(child)
        for n in self.bookmarks:
            clear_node_color(n)
        self.save()
        ida_kernwin.msg("[AddressGrouping] 已清除所有节点颜色\n")

# PyQt5树状窗口
class BookmarkTreeForm(ida_kernwin.PluginForm):
    def __init__(self, manager):
        super().__init__()
        self.manager = manager
        self.tree = None
        self.manager.set_refresh_callback(self.refresh_tree_if_ready)
        self._ready = False

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()
        # 按钮区
        btn_layout = QtWidgets.QHBoxLayout()
        btn_expand = QtWidgets.QPushButton("全部展开")
        btn_collapse = QtWidgets.QPushButton("全部折叠")
        btn_expand.clicked.connect(self.tree_expand_all)
        btn_collapse.clicked.connect(self.tree_collapse_all)
        btn_layout.addWidget(btn_expand)
        btn_layout.addWidget(btn_collapse)
        layout.addLayout(btn_layout)
        # 树控件
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(["节点", "类型", "备注"])
        self.tree.setColumnWidth(0, 400)
        self.tree.setColumnWidth(1, 100)
        self.tree.setColumnWidth(2, 300)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_context_menu)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)
        self._ready = True
        self.refresh_tree()

    def tree_expand_all(self):
        self.tree.expandAll()
    def tree_collapse_all(self):
        self.tree.collapseAll()

    def refresh_tree_if_ready(self):
        if self._ready and self.tree:
            self.refresh_tree()

    def refresh_tree(self):
        if not self.tree:
            return
        self.tree.clear()
        def add_items(parent, nodes):
            for node in nodes:
                item = QtWidgets.QTreeWidgetItem([
                    node["name"],
                    "地址" if node["is_addr"] else "分组/节点",
                    node.get("comment", "")
                ])
                # 恢复颜色
                color = node.get("color")
                if color:
                    color_map = {
                        "red": QtGui.QColor(255, 204, 204),      # 淡红色
                        "green": QtGui.QColor(204, 255, 204),    # 淡绿色
                        "yellow": QtGui.QColor(255, 255, 204),   # 淡黄色
                        "gray": QtGui.QColor(220, 220, 220),     # 淡灰色
                    }
                    brush = QtGui.QBrush(color_map.get(color, QtCore.Qt.white))
                    for col in range(item.columnCount()):
                        item.setBackground(col, brush)
                parent.addChild(item) if parent else self.tree.addTopLevelItem(item)
                add_items(item, node["children"])
        add_items(None, self.manager.bookmarks)
        self.tree.expandAll()

    def get_item_path(self, item):
        path = []
        while item:
            path.insert(0, item.text(0))
            item = item.parent()
        return path

    def on_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        menu = QtWidgets.QMenu()
        if item:
            self.tree.setCurrentItem(item)
            # 分组节点右键：增加"展开本分组全部节点"
            if item.parent() is None:
                act_expand_group = menu.addAction("展开本分组全部节点")
                act_expand_group.triggered.connect(lambda: self.expand_item_recursively(item))
            # 添加子节点
            act_add_child = menu.addAction("添加子节点")
            act_add_child.triggered.connect(self.add_child)
            # 设置备注（仅地址或自定义节点）
            if item.text(1) == "地址" or item.text(1) == "分组/节点":
                act_set_comment = menu.addAction("设置备注")
                act_set_comment.triggered.connect(self.set_comment)
            # 标记颜色
            color_menu = menu.addMenu("标记颜色")
            act_red = color_menu.addAction("红色")
            act_green = color_menu.addAction("绿色")
            act_yellow = color_menu.addAction("黄色")
            act_gray = color_menu.addAction("灰色")
            act_none = color_menu.addAction("无")
            act_red.triggered.connect(lambda: self.set_item_color(item, "red"))
            act_green.triggered.connect(lambda: self.set_item_color(item, "green"))
            act_yellow.triggered.connect(lambda: self.set_item_color(item, "yellow"))
            act_gray.triggered.connect(lambda: self.set_item_color(item, "gray"))
            act_none.triggered.connect(lambda: self.set_item_color(item, None))
            # 删除节点
            if item.parent() is None:
                act_del = menu.addAction("删除分组")
                act_del.triggered.connect(self.del_group)
            else:
                if item.text(1) == "地址":
                    act_del = menu.addAction("删除地址")
                    act_del.triggered.connect(self.del_addr)
                else:
                    act_del = menu.addAction("删除节点")
                    act_del.triggered.connect(self.del_child)
        else:
            act_add_group = menu.addAction("添加分组")
            act_add_group.triggered.connect(self.add_group)
            act_clear_colors = menu.addAction("清除所有颜色")
            act_clear_colors.triggered.connect(self.clear_all_colors)
            # About 菜单项，紧跟在清除所有颜色下方
            act_about = menu.addAction("关于 AddressGrouping")
            act_about.triggered.connect(show_about_dialog)
        menu.exec_(self.tree.viewport().mapToGlobal(pos))

    def add_group(self):
        group = ida_kernwin.ask_str("", 0, "输入新分组名：")
        if group:
            self.manager.add_group(group)

    def del_group(self):
        item = self.tree.currentItem()
        if item and item.parent() is None:
            group = item.text(0)
            self.manager.del_group(group)

    def add_child(self):
        item = self.tree.currentItem()
        if not item:
            return
        path = self.get_item_path(item)
        # 询问类型
        typ = QtWidgets.QInputDialog.getItem(self.tree, "选择类型", "子节点类型：", ["地址", "自定义节点"], 0, False)[0]
        if typ == "地址":
            ea = idc.here()
            name = hex(ea)
            is_addr = True
        else:
            name, ok = QtWidgets.QInputDialog.getText(self.tree, "输入节点名", "节点名：")
            if not ok or not name:
                return
            is_addr = False
        self.manager.add_child(path, name, is_addr)

    def del_child(self):
        item = self.tree.currentItem()
        if not item or not item.parent():
            return
        parent_path = self.get_item_path(item.parent())
        name = item.text(0)
        self.manager.del_child(parent_path, name)

    def add_addr(self):
        item = self.tree.currentItem()
        if item and item.parent() is None:
            group = item.text(0)
            ea = idc.here()
            self.manager.add_addr(group, ea)

    def del_addr(self):
        item = self.tree.currentItem()
        if item and item.parent() is not None and item.text(1) == "地址":
            group = item.parent().text(0)
            addr = int(item.text(0), 16)
            self.manager.del_addr(group, addr)

    def on_double_click(self, item, col):
        if item.text(1) == "地址":
            ea = int(item.text(0), 16)
            ida_kernwin.jumpto(ea)

    def set_comment(self):
        item = self.tree.currentItem()
        if not item:
            return
        path = self.get_item_path(item)
        old_comment = item.text(2)
        comment, ok = QtWidgets.QInputDialog.getText(self.tree, "设置备注", "备注：", text=old_comment)
        if ok:
            self.manager.set_comment(path, comment)

    def set_item_color(self, item, color):
        path = self.get_item_path(item)
        self.manager.set_color(path, color)
        # 刷新后重新选中原节点
        self.refresh_tree()
        self.select_item_by_path(path)

    def select_item_by_path(self, path):
        def find_item(parent, path, depth):
            count = parent.childCount() if parent else self.tree.topLevelItemCount()
            for i in range(count):
                child = parent.child(i) if parent else self.tree.topLevelItem(i)
                if child.text(0) == path[depth]:
                    if depth == len(path) - 1:
                        self.tree.setCurrentItem(child)
                        return True
                    if find_item(child, path, depth + 1):
                        return True
            return False
        find_item(None, path, 0)

    def clear_all_colors(self):
        self.manager.clear_all_colors()
        self.refresh_tree()

    def expand_item_recursively(self, item):
        item.setExpanded(True)
        for i in range(item.childCount()):
            self.expand_item_recursively(item.child(i))

    def OnClose(self, form):
        self._ready = False

# 全局唯一窗口实例
treeform_instance = None

# 注册IDA主界面右键菜单action
def register_mainview_actions(manager):
    # 添加分组
    class AddGroupAction(idaapi.action_handler_t):
        def activate(self, ctx):
            group = ida_kernwin.ask_str("", 0, "输入新分组名：")
            if group:
                manager.add_group(group)
            return 1
        def update(self, ctx):
            if hasattr(ctx, 'widget_type') and ctx.widget_type in [idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM]:
                idaapi.attach_action_to_popup(ctx.widget, None, "AddressGrouping:AddGroup", "AddressGrouping/")
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET
    idaapi.register_action(idaapi.action_desc_t(
        "AddressGrouping:AddGroup", "添加分组", AddGroupAction()))

    # 添加地址
    class AddAddrAction(idaapi.action_handler_t):
        def activate(self, ctx):
            groups = manager.get_groups()
            if not groups:
                ida_kernwin.msg("[AddressGrouping] 请先添加分组！\n")
                return 1
            group = select_group(groups)
            if group:
                ea = ctx.cur_ea
                manager.add_addr(group, ea)
            return 1
        def update(self, ctx):
            if hasattr(ctx, 'widget_type') and ctx.widget_type in [idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM]:
                idaapi.attach_action_to_popup(ctx.widget, None, "AddressGrouping:AddAddr", "AddressGrouping/")
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET
    idaapi.register_action(idaapi.action_desc_t(
        "AddressGrouping:AddAddr", "添加地址", AddAddrAction()))

def register_open_action(treeform):
    class create_widget_t(ida_kernwin.action_handler_t):
        def activate(self, ctx):
            treeform.Show(title)
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS

    action_name = "AddressGrouping:Show"
    action_shortcut = "Ctrl+Alt+P"
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            action_name,
            title,
            create_widget_t(),
            action_shortcut))
    ida_kernwin.attach_action_to_menu(
        f"View/Open subviews/{title}",
        action_name,
        ida_kernwin.SETMENU_APP)

def show_about_dialog():
    QtWidgets.QMessageBox.information(
        None,
        "About AddressGrouping",
        (
            "<b>AddressGrouping</b> 插件<br>"
            "<br>"
            "多级分组、备注、彩色高亮、流程分析，助力IDA逆向分析。<br>"
            "<br>"
            "作者：naiyouweibaomihua<br>"
            "仓库地址：<a href='https://github.com/naiyouweibaomihua/IDA_AddressGrouping.git'>https://github.com/naiyouweibaomihua/IDA_AddressGrouping.git</a><br>"
            "<br>"
            "兼容：IDA Pro 7.4+，Python 3.x，PyQt5<br>"
            "协议：MIT License<br>"
            "<br>"
            "欢迎在GitHub提交issue、建议或PR！"
        )
    )

class my_plugin_addrgroup(ida_idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    wanted_name = "AddressGrouping"
    wanted_hotkey = ""
    comment = "AddressGrouping"
    help = ""

    def init(self):
        global treeform_instance
        self.manager = BookmarkManager()
        if treeform_instance is None:
            treeform_instance = BookmarkTreeForm(self.manager)
        register_open_action(treeform_instance)
        register_mainview_actions(self.manager)
        # 自动弹窗：注册UI钩子
        class MyUIHooks(ida_kernwin.UI_Hooks):
            def ready_to_run(hooks_self):
                treeform_instance.Show(title)
                hooks_self.unhook()
        self._ui_hooks = MyUIHooks()
        self._ui_hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        global treeform_instance
        if treeform_instance:
            treeform_instance.Show(title)

    def term(self):
        return

def PLUGIN_ENTRY():
    return my_plugin_addrgroup() 