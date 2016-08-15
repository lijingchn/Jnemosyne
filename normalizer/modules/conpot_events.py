# Copyright (C) 2013 Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import json

from normalizer.modules.basenormalizer import BaseNormalizer


class Conpot(BaseNormalizer):
    channels = ('conpot.events',)

    def normalize(self, data, channel, submission_timestamp, ignore_rfc1918=True):
        o_data = self.parse_record_data(data)

        if ignore_rfc1918 and self.is_RFC1918_addr(o_data['remote'][0]):
            return []


        all_protocol = {'http':80,'s7comm':102,'modbus':502, 'ipmi':623, 'snmp':161, 'hmi':0,
                'RealPort':771,'Red Lion':789,'Codesys':1200,'Tridium Fox':1911,
                'PCWorx':1962, 'GPRS Tunneling':2123, 'IEC104':2404, 'Codesys':2455,
                'Tridium Fox SSL':4991, 'Mitsubishi MELSEC':5006, 'HART-IP':5094,
                'OMRON FINS':9600, 'Vxworks WDB':17185, 'GE SRTP':18245, 'DNP3':20000,
                'ProConOS':20547, 'Lantronix':30718, 'Profinet':34962, 'Dahua Dvr':37777,
                'EtherNet/IP':44818, 'bacnet':47808,}

        session = {
            'timestamp': submission_timestamp,
            'source_ip': o_data['remote'][0],
            'source_port': o_data['remote'][1],
#            'destination_port': 502,
            'destination_ip': o_data['public_ip'],
            'destination_port': all_protocol[o_data['data_type']],
            'honeypot': 'conpot',
            'protocol': o_data['data_type'],
            'session_{0}'.format(o_data['data_type']): { 'pdus': o_data['data']}

            }

        relations = [{'session': session},]

        return relations
