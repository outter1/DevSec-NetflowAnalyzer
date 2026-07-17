# SPDX-License-Identifier: MIT
# Copyright (c) 2026 KillChain
# Copyright (c) 2026 Gabriel Silva Bastos
# Copyright (c) 2026 Matheus Dominato
# Copyright (c) 2026 Isabelle Guimarães de Andrade
# Copyright (c) 2026 Nicolas Urtiaga
# Copyright (c) 2026 Pedro Lages da Silva

"""Entrada da interface desktop do DevSec - NetFlow Analyzer."""

from ui.main_window import MainWindow


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
