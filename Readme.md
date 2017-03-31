# wireshark-plugin-afdx

**wireshark-plugin-afdx** is the [Wireshark] plugin (dissector) for [ARINC 664 / AFDX][AFDX] written by [REDLAB-I, LLC][REDLAB-I].

wireshark-plugin-afdx's homepage is located on [GitHub][homepage].

# Fuctions

* Parse and display AFDX-specific headers
* Translate addresses to system defined names
* Check VL correctness (id, mtu, BAG, jitter)
* Use AFDX-specific fields in filters

# Build & installation

You need the following packages installed in your system:
- wireshark-dev
- libglib2.0-dev
- gettext
- cmake

Follow these steps:
* Unpack archive or clone git repository.
* Enter source's directory.
* Create build directory and enter it (e.g. *mkdir build&&cd build*)
* Call cmake: *cmake ..*
* Build: *make*
* Install: *make install*

By default plugin will be intalled to system-wide directory: */usr/lib/<arch>/wireshark/<version>/plugins*.
If you want to install it only for current user, specify installation directory manually when configure (e.g. *cmake -D CMAKE_INSTALL_LIBDIR=~/.wireshark/plugins ..*).

On Debian system you can build deb-packages from *debian* branch in git repository with *dpkg-buildpackage*.

# Usage

TODO: Copy usage info from ReadmeRus.txt

# License
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# Contacts
For any reason you can contact authors using *Issues* webinterface on GitHub, or mail directly to info@redlab-i.ru.

[Wireshark]: <https://wireshark.org>
[AFDX]: <https://en.wikipedia.org/wiki/Avionics_Full-Duplex_Switched_Ethernet>
[REDLAB-I]: <http://redlab-i.ru>
[homepage]: <https://github.com/redlab-i/wireshark-plugin-afdx>
