#!/usr/bin/env python

import os
import sys
import random

import kblib

from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QScrollArea, QGroupBox, QSizePolicy
from PyQt5.QtGui import QPalette, QColor, QPainter, QBrush, QPen, QFont, QFontMetrics
from PyQt5.QtCore import Qt, QRect, QSize

database = None

PATH_WIKI = os.path.join(os.environ['HOME'], 'fdumps', 'wiki')

pastel1 = [
(0xB3, 0xCD, 0xE3),
(0xCC, 0xEB, 0xC5),
(0xDE, 0xCB, 0xE4),
(0xE5, 0xD8, 0xBD),
(0xF2, 0xF2, 0xF2),
(0xFB, 0xB4, 0xAE),
(0xFD, 0xDA, 0xEC),
(0xFE, 0xD9, 0xA6),
(0xFF, 0xFF, 0xCC)
]

def fsize_to_string(fsize):
    if fsize < 1024:
        return f'{fsize}b'
    if fsize < 1024*1024:
        return f'{fsize//1024}kb'
    return f'{fsize//(1024*1024)}mb'

def measure_text(font, msg):
    fmetrics = QFontMetrics(font)
    return(fmetrics.width(msg), fmetrics.height())

class Card(QWidget):
    def __init__(self, fpath):
        global database

        super(Card, self).__init__()

        self.fpath = fpath
        self.fname = os.path.split(fpath)[1]
        self.color = QColor(*random.choice(pastel1))
        self.date_edited = database[self.fname]['date_edited']

        # sizePolicy()
        #   https://doc.qt.io/qt-5/qwidget.html#sizePolicy-prop
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    # triggered by
    # - repaint() or update()
    # - widget was obscured and has now been uncovered
    # - widget has been resized
    def paintEvent(self, event):
        painter = QPainter(self)

        brush = QBrush()
        brush.setStyle(Qt.SolidPattern)

        widget_width = painter.device().width()
        widget_height = painter.device().height()

        # do shadow
        brush.setColor(QColor(0xA0, 0xA0, 0xA0))
        rect = QRect(2, 2, widget_width-4, widget_height-4)
        painter.fillRect(rect, brush)

        # do normal
        brush.setColor(self.color)
        rect = QRect(0, 0, widget_width-4, widget_height-4)
        painter.fillRect(rect, brush)

        # do border
        painter.setPen(Qt.black)
        painter.drawRect(0, 0, widget_width-5, widget_height-5)
        
        font = QFont()
        font.setFamily('Tahoma')
        font.setBold(True)

        (_, fname) = os.path.split(self.fpath)
        msg = f' {fname} '
        font_size = 1
        while True:
            font.setPixelSize(font_size)
            (text_width, text_height) = measure_text(font, msg)
            if text_width >= widget_width or text_height > 40:
                font_size -= 1
                break
            font_size += 1

        font.setPixelSize(font_size)
        (text_width, text_height) = measure_text(font, msg)
        painter.setFont(font)

        painter.drawText(widget_width//2 - text_width//2, widget_height//2, msg)

        # draw file size
        fsize = os.path.getsize(self.fpath)
        font.setPixelSize(8)
        painter.setFont(font)
        painter.drawText(2, widget_height-8, fsize_to_string(fsize))

        # draw date edited
        msg = kblib.pretty_time_ago(self.date_edited)
        (text_width, text_height) = measure_text(font, msg)
        painter.drawText(2, text_height, msg)

    # sizeHint()
    #   https://doc.qt.io/qt-5/qwidget.html#sizeHint-prop

    def sizeHint(self):
        return QSize(160, 120)
    
    def minimumSizeHint(self):
        return QSize(160, 120)

    def mouseDoubleClickEvent(self, event):
        os.system('open ' + self.fpath)

class MainWindow(QMainWindow):
    def __init__(self):
        global database

        super(MainWindow, self).__init__()

        self.setWindowTitle("Notes")

        col0 = QVBoxLayout()
        col1 = QVBoxLayout()
        col2 = QVBoxLayout()

        for fname in sorted(database, key=lambda k: database[k]['date_edited'], reverse=True):
            fpath = os.path.join(kblib.PATH_KB, fname)

            # get the layout with the least elements
            layout = sorted([col0, col1, col2], key = lambda x: x.count())[0]
            # add to it
            layout.addWidget(Card(fpath))
            
        layout_cols = QHBoxLayout()
        layout_cols.addLayout(col0)
        layout_cols.addLayout(col1)
        layout_cols.addLayout(col2)

        #layout_cards.setContentsMargins(0, 0, 0, 0) # spacing around elements
        #layout_cards.setSpacing(0) # spacing between elements

        groupBox = QGroupBox()
        groupBox.setStyleSheet("background-color: #FFF9EE")
        groupBox.setLayout(layout_cols)

        scroll = QScrollArea()
        scroll.setWidget(groupBox)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        #scroll.setFixedHeight(200)

        self.setCentralWidget(scroll)

database = kblib.db_load()

app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()

