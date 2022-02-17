import operator

from binaryninja import BinaryView, log
from binaryninjaui import (
    DockHandler,
    DockContextHandler,
    ThemeColor,
    UIActionHandler,
    getMonospaceFont,
    getThemeColor
)

from PySide2 import QtCore
from PySide2.QtGui import QFontMetrics
from PySide2.QtCore import Qt, QAbstractTableModel, SIGNAL
from PySide2.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QDockWidget,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QWidget,
    QTableView
)


class DelphiVmtModel(QAbstractTableModel):
    COL_ADDRESS = 0
    COL_CLASSNAME = 1


    def __init__(self, parent, vmts, *args):
        QAbstractTableModel.__init__(self, parent, *args)
        self._headers = ['Location', 'Class Name']
        self._vmts = []


    def rowCount(self, parent):
        return len(self._vmts)


    def columnCount(self, parent):
        return len(self._headers)


    def headerData(self, col, orientation, role):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self._headers[col]


    def data(self, index, role):
        row = index.row()
        col = index.column()

        if not index.isValid():
            return

        if role == Qt.ForegroundRole and col == self.COL_ADDRESS:
            return getThemeColor(ThemeColor.AddressColor)

        elif role == Qt.DisplayRole:
            vmt = self._vmts[row]

            if col == self.COL_ADDRESS:
                return f'{vmt[col]:08x}'

            return vmt[col]


    def sort(self, col, order):
        self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self._vmts = sorted(self._vmts, key=operator.itemgetter(col))

        if order == Qt.DescendingOrder:
            self._vmts.reverse()

        self.emit(SIGNAL("layoutChanged()"))


    # Public API

    def clear_vmts(self):
        self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self._vmts = []
        self.emit(SIGNAL("layoutChanged()"))


    def set_vmts(self, vmts):
        self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self._vmts = vmts
        self.emit(SIGNAL("layoutChanged()"))


    def add_vmt(self, address, class_name):
        self.emit(SIGNAL("layoutAboutToBeChanged()"))
        self._vmts.append((address, class_name))
        self.emit(SIGNAL("layoutChanged()"))


    # Properties

    @property
    def vmts(self):
        return self._vmts


class DelphiVmtWidget(QWidget, DockContextHandler):
    COL_ADDRESS = 0

    def __init__(self, parent, name, initial_data=[]):
        QWidget.__init__(self, parent)
        DockContextHandler.__init__(self, self, name)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        self._bv = None

        self._table_model = DelphiVmtModel(self, initial_data)
        self._table_view = QTableView()
        self._table_view.setModel(self._table_model)

        font = getMonospaceFont(self)
        font_metrics = QFontMetrics(font)
        self._table_view.setFont(font)
        self._table_view.setColumnWidth(0, 10 * font_metrics.averageCharWidth())
        self._table_view.horizontalHeader().setStretchLastSection(True)
        self._table_view.setSortingEnabled(True)
        self._table_view.sortByColumn(self.COL_ADDRESS, Qt.SortOrder.AscendingOrder)
        self._table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table_view.doubleClicked.connect(self.onCellDoubleClicked)

        layout = QVBoxLayout(self)
        layout.addWidget(self._table_view)
        self.setLayout(layout)


    def shouldBeVisible(self, view_frame):
        return view_frame is not None


    def notifyViewChanged(self, view_frame):
        if view_frame is None:
            self._bv = None
            return

        self._bv = view_frame.actionContext().binaryView


    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


    def onCellDoubleClicked(self, item):
        address = self._table_model.vmts[item.row()][self.COL_ADDRESS]
        self._bv.file.navigate(self._bv.file.view, address)


    # Public API

    @staticmethod
    def create_dock_widget():
        window = QApplication.allWidgets()[0].window()
        dock_handler = window.findChild(DockHandler, '__DockHandler')

        vmt_dock_widget = DelphiVmtWidget._create_widget('Delphi VMTs', dock_handler.parent())
        dock_handler.addDockWidget(vmt_dock_widget, Qt.LeftDockWidgetArea, Qt.Horizontal, True)
        return vmt_dock_widget
        # dock_handler.addDockWidget(
        #     'Delphi VMTs',
        #     DelphiVmtWidget._create_widget,
        #     Qt.LeftDockWidgetArea,
        #     Qt.Vertical,
        #     True
        # )


    def clear_vmts(self):
        self._table_model.clear_vmts()


    def set_vmts(self, vmts):
        self._table_model.set_vmts(vmts)


    def add_vmt(self, address, class_name):
        self._table_model.add_vmt(address, class_name)


    # Protected methods

    @staticmethod
    def _create_widget(name, parent, bv=None):
        if bv is not None and not isinstance(bv, BinaryView):
            raise RuntimeError('`bv` must be a Binaryview')

        widget = DelphiVmtWidget(parent, name)

        if bv is not None:
            print(bv)
            bv.delphi_vmt_widget = widget
            setattr(bv, 'delphi_vmt_widget', widget)

        return widget
