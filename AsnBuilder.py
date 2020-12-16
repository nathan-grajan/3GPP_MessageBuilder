from pycrate_asn1dir import RRCLTE
import json
from pycrate_asn1rt.asnobj_class import *

intDefaultValues = {
    'srb-Identity-v1530': 4,
    'RRCTransactionIdentifier': 1
}
# msgType = input("What type of message do you want? ")
msgSequence = ['RRCConnectionRequest', 'RRCConnectionSetup', 'RRCConnectionSetupComplete',
               'RRCConnectionReconfiguration', 'RRCConnectionReconfigurationComplete', 'DLInformationTransfer',
               'ULInformationTransfer']


def main():
    sch = RRCLTE.EUTRA_RRC_Definitions()
    msgDict = dict()
    for msgType in msgSequence:
        rcs = getattr(sch, msgType)
        ncs = builder(rcs)
        rcsAsn = rcs.to_asn1()
        msgDict.update({msgType: rcsAsn})
    print(msgDict)

def builder(rcs):
    if rcs.TYPE == "SEQUENCE":
        rcs._val = dict()
        for key in rcs._cont._dict:
            seqElem = rcs._cont._dict[key]
            if ~(((seqElem.TYPE == 'BIT STRING') or (seqElem.TYPE == 'OCTET STRING')) and (seqElem._opt == True)):
                seqValue = builder(rcs._cont._dict[key])
                rcs._val.update({key: seqValue})
    elif rcs.TYPE == "INTEGER":
        rcs._val = rcs._const_val.ub
        # rcs._cont = None
        return rcs._val
    elif rcs.TYPE == "CHOICE":
        choice = rcs._cont._index[0]
        choiceValue = builder(rcs._cont._dict[choice])
        rcs._val = (choice, choiceValue)
        return rcs._val
    elif rcs.TYPE == "BOOLEAN":
        rcs._val = True
        rcs._cont = None
    elif rcs.TYPE == "SEQUENCE OF":
        rcsNew = rcs._cont
        rcs._val = [builder(rcsNew)]
    elif rcs.TYPE == "ENUMERATED":
        # ms key in dictionary
        rcs._val = rcs._cont._index[0]
    elif rcs.TYPE == "NULL":
        rcs._cont = None
        rcs._val = None
    elif rcs.TYPE == 'BIT STRING':
        if rcs._const_sz is None:
            rcs._const_sz = ASN1Set(ev=None)
            rcs._const_sz.ub = 2
            rcs._const_sz.lb = 2
            rcs._const_sz.rdyn = (rcs._const_sz.ub - rcs._const_sz.lb).bit_length()
            rcs._const_sz.ra = 1
            rcs._const_sz._rv = [2]
            rcs._const_sz.root = [2]
            rcs._const_sz._rr = []
            rcs._const_sz._CONTAIN_WEXT = False
            rcs._const_sz._er = []

        size = rcs._const_sz.lb
        bitString = 2 ** size - 2
        rcs._val = (bitString, size)
    elif rcs.TYPE == 'OCTET STRING':
        if rcs._const_sz is None:
            rcs._const_sz = ASN1Set(ev=None)
            rcs._const_sz.ub = 2
            rcs._const_sz.lb = 2
            rcs._const_sz.rdyn = (rcs._const_sz.ub - rcs._const_sz.lb).bit_length()
            rcs._const_sz.ra = 1
            rcs._const_sz._rv = [2]
            rcs._const_sz.root = [2]
            rcs._const_sz._rr = []
            rcs._const_sz._CONTAIN_WEXT = False
            rcs._const_sz._er = []

        size = 2 ** rcs._const_sz.lb
        octetString = 2 ** size - 2
        rcs._val = bytes(octetString)

    else:
        print(rcs._name)
        print(rcs.TYPE)

    return rcs._val

if __name__ == '__main__':
    main()
