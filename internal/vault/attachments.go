package vault

import (
	"github.com/andrew/grafted-secrets/internal/crypto"
	"github.com/andrew/grafted-secrets/internal/store"
)

// AttachmentMeta is the per-file metadata shown in a key's attachment list. It
// never carries the file bytes - those are decrypted only on download.
type AttachmentMeta struct {
	ID          string
	SecretID    string
	Name        string
	Size        int64
	CreatedAt   int64
	DisplayName string
}

// AttachmentData is a fully-decrypted attachment, returned only to the download
// handler behind an explicit user action.
type AttachmentData struct {
	Name string
	Data []byte
}

// sealBytes/openBytes are the binary-payload analogues of seal/field: AES-256-GCM
// under the DEK with role-bound AAD ("gs/attachment/<id>/data"), so a file blob
// is cryptographically pinned to its row and field exactly like every text field.
func (s *Service) sealBytes(dek, pt []byte, entity, id, field string) ([]byte, error) {
	return crypto.Seal(dek, pt, fieldAAD(entity, id, field))
}

func (s *Service) openBytes(dek, blob []byte, entity, id, field string) ([]byte, error) {
	return crypto.Open(dek, blob, fieldAAD(entity, id, field))
}

// Attachments returns the (name-only) attachment metadata for a secret. File
// bytes are never decrypted here, so a key's detail view never materializes a
// payload until the user downloads it.
func (s *Service) Attachments(dek []byte, secretID string) ([]AttachmentMeta, error) {
	rows, err := s.db.ListAttachments(secretID)
	if err != nil {
		return nil, err
	}
	out := make([]AttachmentMeta, 0, len(rows))
	for _, r := range rows {
		name, err := s.field(dek, r.NameEnc, "attachment", r.ID, "name")
		if err != nil {
			return nil, err
		}
		var displayName string
		if len(r.DisplayNameEnc) > 0 {
			displayName, err = s.field(dek, r.DisplayNameEnc, "attachment", r.ID, "display_name")
			if err != nil {
				return nil, err
			}
		}
		out = append(out, AttachmentMeta{
			ID: r.ID, SecretID: r.SecretID, Name: name, Size: r.Size, CreatedAt: r.CreatedAt, DisplayName: displayName,
		})
	}
	return out, nil
}

// CountAttachments reports how many files a secret has (for the list header /
// has-attachments indicator) without decrypting anything.
func (s *Service) CountAttachments(secretID string) (int, error) {
	return s.db.CountAttachments(secretID)
}

// AddAttachment encrypts a file's name and bytes under the DEK and stores them
// against a secret. The caller is responsible for enforcing the size cap before
// calling; Size records the plaintext length for display.
func (s *Service) AddAttachment(dek []byte, secretID, name, displayName string, data []byte) (string, error) {
	id := crypto.RandID()
	ne, err := s.seal(dek, name, "attachment", id, "name")
	if err != nil {
		return "", err
	}
	var dne []byte
	if displayName != "" {
		dne, err = s.seal(dek, displayName, "attachment", id, "display_name")
		if err != nil {
			return "", err
		}
	}
	de, err := s.sealBytes(dek, data, "attachment", id, "data")
	if err != nil {
		return "", err
	}
	return id, s.db.CreateAttachment(store.Attachment{
		ID: id, SecretID: secretID, NameEnc: ne, DisplayNameEnc: dne, DataEnc: de, Size: int64(len(data)),
	})
}

// AttachmentData decrypts a single attachment for download. A GCM auth failure
// (tampered/rolled-back/substituted blob, or wrong key) surfaces as an error
// rather than serving forged bytes.
func (s *Service) AttachmentData(dek []byte, id string) (AttachmentData, error) {
	r, err := s.db.GetAttachment(id)
	if err != nil {
		return AttachmentData{}, err
	}
	name, err := s.field(dek, r.NameEnc, "attachment", r.ID, "name")
	if err != nil {
		return AttachmentData{}, err
	}
	data, err := s.openBytes(dek, r.DataEnc, "attachment", r.ID, "data")
	if err != nil {
		return AttachmentData{}, err
	}
	return AttachmentData{Name: name, Data: data}, nil
}

func (s *Service) DeleteAttachment(id string) error { return s.db.DeleteAttachment(id) }

// AttachmentSecret returns the id of the secret an attachment belongs to.
func (s *Service) AttachmentSecret(id string) (string, error) {
	return s.db.AttachmentSecretID(id)
}

// AttachmentMeta loads and decrypts a single attachment's metadata by ID.
func (s *Service) AttachmentMeta(dek []byte, id string) (AttachmentMeta, error) {
	r, err := s.db.GetAttachment(id)
	if err != nil {
		return AttachmentMeta{}, err
	}
	name, err := s.field(dek, r.NameEnc, "attachment", r.ID, "name")
	if err != nil {
		return AttachmentMeta{}, err
	}
	var displayName string
	if len(r.DisplayNameEnc) > 0 {
		displayName, err = s.field(dek, r.DisplayNameEnc, "attachment", r.ID, "display_name")
		if err != nil {
			return AttachmentMeta{}, err
		}
	}
	return AttachmentMeta{
		ID: r.ID, SecretID: r.SecretID, Name: name, Size: r.Size, CreatedAt: r.CreatedAt, DisplayName: displayName,
	}, nil
}

// UpdateAttachmentDisplayName encrypts the new display name and updates it in the store.
func (s *Service) UpdateAttachmentDisplayName(dek []byte, id, displayName string) error {
	var dne []byte
	var err error
	if displayName != "" {
		dne, err = s.seal(dek, displayName, "attachment", id, "display_name")
		if err != nil {
			return err
		}
	}
	return s.db.UpdateAttachmentDisplayName(id, dne)
}
