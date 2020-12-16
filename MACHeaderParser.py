from pycrate_asn1dir import RRCLTE
from binascii import unhexlify, hexlify
import json
import re
import enum


class LogicChannel(enum.Enum):
    CCCH = 0
    DCCH = 1
    PADDING = 2


class SchDirection(enum.Enum):
    UPLINK = 0
    DOWNLINK = 1


def main():
    detectedDirection = SchDirection.DOWNLINK

    # Read in file
    f = open('rrcEx.txt', "r")
    msg = f.read()
    msgStrip = msg.replace(" ", "").replace("\n", "")
    # Ask user for parameter
    parameterWant = input("What parameter do you want? ")
    rawData = unhexlify(msgStrip)
    arrayHeader = processMACHeader(rawData)

    firstSub = arrayHeader[0]
    LCID = firstSub['LCID']
    if detectedDirection == SchDirection.DOWNLINK:

        if LCID == 0:
            sch = RRCLTE.EUTRA_RRC_Definitions.DL_CCCH_Message
        else:
            sch = RRCLTE.EUTRA_RRC_Definitions.DL_DCCH_Message
    else:
        if LCID == 0:
            sch = RRCLTE.EUTRA_RRC_Definitions.UL_CCCH_Message
        else:
            sch = RRCLTE.EUTRA_RRC_Definitions.UL_DCCH_Message
    macLength = 0
    for i in arrayHeader:
        macLength += i['Subheader_length'] * 2
    msgToProcess = msgStrip[macLength:]
    #sch = RRCLTE.EUTRA_RRC_Definitions.DL_CCCH_Message
    #a = sch.to_json()
    #sch.message = "DL-CCCH-Message"
    #sch.messageType = "rrcConnectionSetup"
    #sch.set_val({"message": {"c1": {"rrcConnectionSetup": {}}}})
    unh = unhexlify("60129B3E860FB579E8966C306499602C7800")
    sch.from_uper(unh)

    print("**************************** orig rrc conn setup ******")

    #print(sch.to_asn1())
    schjson = sch.to_json()
    schjson = replace_values(schjson, 'c1', 'noon')
    print(schjson)

    print("****************************  rrc conn setup ******")

    decoded_rrc = {'rrcConnectionSetup': {'criticalExtensions': {'c1': {'rrcConnectionSetup-r8': {'radioResourceConfigDedicated': {'mac-MainConfig': {'explicitValue': {'drx-Config': {'release': None}, 'phr-Config': {'setup': {'dl-PathlossChange': 'dB3', 'periodicPHR-Timer': 'sf500', 'prohibitPHR-Timer': 'sf200'}}, 'timeAlignmentTimerDedicated': 'infinity', 'ul-SCH-Config': {'maxHARQ-Tx': 'n5', 'periodicBSR-Timer': 'sf20', 'retxBSR-Timer': 'sf320', 'ttiBundling': False}}}, 'physicalConfigDedicated': {'antennaInfo': {'defaultValue': None}, 'cqi-ReportConfig': {'cqi-ReportModeAperiodic': 'rm30', 'nomPDSCH-RS-EPRE-Offset': 0}, 'pdsch-ConfigDedicated': {'p-a': 'dB-3'}, 'pucch-ConfigDedicated': {'ackNackRepetition': {'release': None}}, 'pusch-ConfigDedicated': {'betaOffset-ACK-Index': 9, 'betaOffset-CQI-Index': 6, 'betaOffset-RI-Index': 6}, 'schedulingRequestConfig': {'setup': {'dsr-TransMax': 'n4', 'sr-ConfigIndex': 30, 'sr-PUCCH-ResourceIndex': 11}}, 'soundingRS-UL-ConfigDedicated': {'release': None}, 'uplinkPowerControlDedicated': {'accumulationEnabled': True, 'deltaMCS-Enabled': 'en0', 'filterCoefficient': 'fc4', 'p0-UE-PUCCH': 0, 'p0-UE-PUSCH': 0, 'pSRS-Offset': 3}}, 'srb-ToAddModList': [{'logicalChannelConfig': {'defaultValue': None}, 'rlc-Config': {'defaultValue': None}, 'srb-Identity': 1}]}}}}, 'rrc-TransactionIdentifier': 0}}

    rrccs = RRCLTE.EUTRA_RRC_Definitions.RRCConnectionSetup

    rrc = RRCLTE.EUTRA_RRC_Definitions.DL_CCCH_Message
    rrc._SAFE_INIT = False
    rrc._SAFE_VAL = False
    rrc._SAFE_BND = False
    rrc._SAFE_BNDTAB = False
    rrc.set_val(decoded_rrc)
    print(rrc.to_json())


    nonString = json.loads(sch.to_json())

    extracted = extract_values(nonString, parameterWant)

    print(extracted)

    replaced = replace_values(decoded_rrc, 'release', 'noon')
    print(replaced)
    return


def compareE(subheader):
    eBitLocation = b'\x20'
    return (eBitLocation[0] & subheader[0]) > 0


def compareLCID(subheader):
    LCIDLocation = b'\x1F'
    return LCIDLocation[0] & subheader[0]


def processSubheader(subheader):
    eBit = compareE(subheader)
    LCID = compareLCID(subheader)
    lField = 0
    d = dict()
    d['LCID'] = LCID
    d['Subheader_length'] = 1
    if eBit:
        nextByte = subheader[1]

        fLocation = b'\x80'
        # Find value of fBit
        fBit = (fLocation[0] & nextByte) > 0
        # if fBit is 1, L is 15 bits. Else L is 7 bits.
        if fBit:
            combineData = subheader[1:2]
            # L is length of data in MAC header
            lField = b'\x7F\xFF' & combineData[0:1]
            d['Subheader_length'] = 3

        else:
            lField = ~(fLocation[0]) & nextByte
            d['Subheader_length'] = 2

    d['lField'] = lField
    return d


def processMACHeader(rawData):
    processingMac = True
    headerIndex = 0
    arrayHeader = []
    while processingMac:
        d = processSubheader(rawData[headerIndex:])
        headerIndex += d['Subheader_length']
        if d['LCID'] == 31:
            # if 31 because that's 1F which is padding
            processingMac = False
        arrayHeader.append(d)

    return arrayHeader



def extract_values(obj, key):
    """Pull all values of specified key from nested JSON."""
    arr = []

    def extract(obj, arr, key):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    if k == key:
                        arr.append(v)
                    extract(v, arr, key)
                elif k == key:
                    arr.append(v)
        elif isinstance(obj, list):
            for item in obj:
                extract(item, arr, key)
        return arr

    results = extract(obj, arr, key)
    return results


def replace_values(obj, key, replacement):
    """Pull all values of specified key from nested JSON."""


    def replace(obj, key, replacement):
        """Recursively search for values of key in JSON tree."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    if k == key:
                        obj[k] = replacement
                    replace(v, key, replacement)
                elif k == key:
                    obj[k] = replacement
        elif isinstance(obj, list):
            for item in obj:
                replace(item, key, replacement)
        return

    replace(obj, key, replacement)
    return obj

if __name__ == '__main__':
    main()
