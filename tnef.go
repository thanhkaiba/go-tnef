// Package tnef extracts the body and attachments from Microsoft TNEF files.
package tnef // import "github.com/teamwork/tnef"

import (
	"encoding/binary"
	"errors"
	"io/ioutil"
	"strings"
)

const (
	tnefSignature = 0x223e9f78
	//lvlMessage    = 0x01
	lvlAttachment = 0x02

	MIN_OBJ_SIZE = 12
)

// These can be used to figure out the type of attribute
// an object is
const (
	ATTOWNER                   = 0x0000 // Owner
	ATTSENTFOR                 = 0x0001 // Sent For
	ATTDELEGATE                = 0x0002 // Delegate
	ATTDATESTART               = 0x0006 // Date Start
	ATTDATEEND                 = 0x0007 // Date End
	ATTAIDOWNER                = 0x0008 // Owner Appointment ID
	ATTREQUESTRES              = 0x0009 // Response Requested.
	ATTFROM                    = 0x8000 // From
	ATTSUBJECT                 = 0x8004 // Subject
	ATTDATESENT                = 0x8005 // Date Sent
	ATTDATERECD                = 0x8006 // Date Received
	ATTMESSAGESTATUS           = 0x8007 // Message Status
	ATTMESSAGECLASS            = 0x8008 // Message Class
	ATTMESSAGEID               = 0x8009 // Message ID
	ATTPARENTID                = 0x800a // Parent ID
	ATTCONVERSATIONID          = 0x800b // Conversation ID
	ATTBODY                    = 0x800c // Body
	ATTPRIORITY                = 0x800d // Priority
	ATTATTACHDATA              = 0x800f // Attachment Data
	ATTATTACHTITLE             = 0x8010 // Attachment File Name
	ATTATTACHMETAFILE          = 0x8011 // Attachment Meta File
	ATTATTACHCREATEDATE        = 0x8012 // Attachment Creation Date
	ATTATTACHMODIFYDATE        = 0x8013 // Attachment Modification Date
	ATTDATEMODIFY              = 0x8020 // Date Modified
	ATTATTACHTRANSPORTFILENAME = 0x9001 // Attachment Transport Filename
	ATTATTACHRENDDATA          = 0x9002 // Attachment Rendering Data
	ATTMAPIPROPS               = 0x9003 // MAPI Properties
	ATTRECIPTABLE              = 0x9004 // Recipients
	ATTATTACHMENT              = 0x9005 // Attachment
	ATTTNEFVERSION             = 0x9006 // TNEF Version
	ATTOEMCODEPAGE             = 0x9007 // OEM Codepage
	ATTORIGNINALMESSAGECLASS   = 0x9008 // Original Message Class
)

type TNEFObject struct {
	Level  uint8
	Name   uint16
	Type   uint16
	Data   []byte
	Length uint32
}

// Attachment contains standard attachments that are embedded
// within the TNEF file, with the name and data of the file extracted.
type Attachment struct {
	Title            string
	Data             []byte
	ModificationDate []byte
	CreationDate     []byte
}

// ErrNoMarker signals that the file did not start with the fixed TNEF marker,
// meaning it's not in the TNEF file format we recognize (e.g. it just has the
// .tnef extension, or a wrong MIME type).
var ErrNoMarker = errors.New("Wrong TNEF signature")

// Data contains the various data from the extracted TNEF file.
type Data struct {
	Body        []byte
	BodyHTML    []byte
	Attachments []*Attachment
	Attributes  []MAPIAttribute
	RTFBody     []byte
	key         uint16
}

func (a *Attachment) addAttr(obj *TNEFObject) {

	switch obj.Name {
	case ATTATTACHMODIFYDATE:
		a.ModificationDate = obj.Data
	case ATTATTACHCREATEDATE:
		a.CreationDate = obj.Data
	case ATTATTACHTITLE:
		a.Title = strings.Replace(string(obj.Data), "\x00", "", -1)
	case ATTATTACHDATA:
		a.Data = obj.Data
	case ATTATTACHMENT:
		attributes, err := decodeMapi(obj.Data, 0)
		if err == nil {
			for _, attr := range attributes {
				switch attr.Name {
				case MAPIAttachFilename, MAPIDisplayName:
					a.Title = strings.Replace(string(attr.Data), "\x00", "", -1)
					// case MAPIAttachDataObj:
					// 	if bytes.HasPrefix(obj.Data, IMessageSig) {
					// 		a.Data = obj.Data[IMessageSigLen:]
					// 		a.Embed, _ = Decode(obj.Data)
					// 	} else {
					// 		a.Data = obj.Data
					// 	}
					// }
				}
			}
		}
	}
}

// DecodeFile is a utility function that reads the file into memory
// before calling the normal Decode function on the data.
func DecodeFile(path string) (*Data, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return Decode(data)
}

// Decode will accept a stream of bytes in the TNEF format and extract the
// attachments and body into a Data object.
func Decode(data []byte) (*Data, error) {

	signature := binary.LittleEndian.Uint32(data)
	if signature != tnefSignature {
		return nil, ErrNoMarker
	}
	tnef := &Data{
		Attachments: []*Attachment{},
	}
	tnef.key = binary.LittleEndian.Uint16(data[4:])

	offset := 6
	var attachment *Attachment

	for offset+MIN_OBJ_SIZE < len(data) {
		obj := decodeTNEFObject(data[offset:])
		offset += int(obj.Length)

		if obj.Name == ATTATTACHRENDDATA {
			attachment = &Attachment{}
			tnef.Attachments = append(tnef.Attachments, attachment)
		} else if obj.Level == lvlAttachment {
			if attachment != nil {
				attachment.addAttr(obj)
			}
		}
	}

	return tnef, nil
}

func decodeTNEFObject(data []byte) (object *TNEFObject) {
	object = &TNEFObject{}
	object.Length = uint32(len(data))
	object.Level = uint8(data[0])
	object.Name = binary.LittleEndian.Uint16(data[1:])
	object.Type = binary.BigEndian.Uint16(data[3:])

	length := binary.LittleEndian.Uint32(data[5:]) + 11
	if length < object.Length {
		object.Length = length
	}

	object.Data = data[9 : object.Length-2]

	return
}
