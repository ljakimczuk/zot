//go:build sync
// +build sync

package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/containerd/platforms"
	godigest "github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/regclient/regclient/types/mediatype"
	"github.com/regclient/regclient/types/ref"

	zerr "zotregistry.dev/zot/errors"
	"zotregistry.dev/zot/pkg/api/constants"
	"zotregistry.dev/zot/pkg/common"
	"zotregistry.dev/zot/pkg/extensions/monitoring"
	"zotregistry.dev/zot/pkg/log"
	"zotregistry.dev/zot/pkg/meta"
	mTypes "zotregistry.dev/zot/pkg/meta/types"
	"zotregistry.dev/zot/pkg/storage"
	storageCommon "zotregistry.dev/zot/pkg/storage/common"
	"zotregistry.dev/zot/pkg/storage/local"
	storageTypes "zotregistry.dev/zot/pkg/storage/types"
)

type DestinationRegistry struct {
	storeController  storage.StoreController
	tempStorage      OciLayoutStorage
	metaDB           mTypes.MetaDB
	log              log.Logger
	desiredPlatforms map[string]struct{}
}

func NewDestinationRegistry(
	storeController storage.StoreController, // local store controller
	tempStoreController storage.StoreController, // temp store controller
	metaDB mTypes.MetaDB,
	log log.Logger,
) Destination {

	dstReg := &DestinationRegistry{
		storeController: storeController,
		tempStorage:     NewOciLayoutStorage(tempStoreController),
		metaDB:          metaDB,
		// first we sync from remote (using containers/image copy from docker:// to oci:) to a temp imageStore
		// then we copy the image from tempStorage to zot's storage using ImageStore APIs
		log:              log,
		desiredPlatforms: map[string]struct{}{},
	}

	for _, p := range desiredPlatforms {
		dstReg.desiredPlatforms[p] = struct{}{}
	}

	return dstReg
}

// Check if image is already synced.
func (registry *DestinationRegistry) CanSkipImage(repo, tag string, digest godigest.Digest) (bool, error) {
	// check image already synced
	imageStore := registry.storeController.GetImageStore(repo)

	manifestBytes, localImageManifestDigest, manifestType, err := imageStore.GetImageManifest(repo, tag)
	if err != nil {
		if errors.Is(err, zerr.ErrRepoNotFound) || errors.Is(err, zerr.ErrManifestNotFound) {
			return false, nil
		}

		registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", tag).
			Err(err).Msg("couldn't get local image manifest")

		return false, err
	}

	if localImageManifestDigest != digest {
		registry.log.Info().Str("repo", repo).Str("reference", tag).
			Str("localDigest", localImageManifestDigest.String()).
			Str("remoteDigest", digest.String()).
			Msg("remote image digest changed, syncing again")

		return false, nil
	}

	/*
		Since Zot creates new index manifests from the upstream index manifests,
		comparing digests is not enough, for users could have added or deleted
		desired platforms in the meantime. Zot needs to check whether what is now
		desired is still on the partial manifest index manifests list.

		If the `dev.zotregistry.image.original-digest` is not found, it means
		manifest is not partial manifest, hence further check is skipped.

		If the `dev.zotregistry.image.original-digest` is found, but desired
		platforms list is now empty, it means all platforms are desired now, hence
		false gets returned.

		If the `dev.zotregistry.image.original-digest` is found and desired
		platforms list is not empty, these platforms get checked against the ones
		currently offered by the partial manifests and if some are missing false
		is returned.

		Otherwise true is returned.
	*/
	if manifestType == ispec.MediaTypeImageIndex || manifestType == mediatype.Docker2ManifestList {
		type manifestIndex struct {
			Manifests   []ispec.Descriptor `json:"manifests"`
			Annotations map[string]string  `json:"annotations,omitempty"`
		}

		var mIndex manifestIndex
		if err = json.Unmarshal(manifestBytes, &mIndex); err != nil {
			registry.log.Error().Err(err).Str("repo", repo).Str("reference", tag).
				Str("localDigest", localImageManifestDigest.String()).
				Msg("invalid JSON")

			return false, err
		}

		if _, ok := mIndex.Annotations[constants.OriginalDigestAnnotation]; !ok {
			registry.log.Info().Str("repo", repo).Str("reference", tag).
				Str("localDigest", localImageManifestDigest.String()).
				Msg("manifest is not partial manifest")

			return true, nil
		}

		if len(registry.desiredPlatforms) == 0 {
			registry.log.Info().Str("repo", repo).Str("reference", tag).
				Str("localDigest", localImageManifestDigest.String()).
				Msg("manifest is partial but now all platforms are desired, syncing again")

			return false, nil
		}

		currentPlatforms := map[string]struct{}{}
		for _, platformManifest := range mIndex.Manifests {
			platform := platforms.Format(*platformManifest.Platform)

			currentPlatforms[platform] = struct{}{}
		}

		for platform, _ := range registry.desiredPlatforms {
			if _, ok := currentPlatforms[platform]; !ok {
				registry.log.Info().Str("repo", repo).Str("reference", tag).
					Str("localDigest", localImageManifestDigest.String()).
					Str("platform", platform).
					Msg("partial manifest does not contain desired platform, syncing again")

				return false, nil
			}
		}
	}

	return true, nil
}

func (registry *DestinationRegistry) GetImageReference(repo, reference string) (ref.Ref, error) {
	return registry.tempStorage.GetImageReference(repo, reference)
}

// finalize a syncing image.
func (registry *DestinationRegistry) CommitAll(repo string, imageReference ref.Ref) error {
	tempImageStore := getImageStoreFromImageReference(repo, imageReference, registry.log)

	defer os.RemoveAll(tempImageStore.RootDir())

	registry.log.Info().Str("syncTempDir", path.Join(tempImageStore.RootDir(), repo)).Str("repository", repo).
		Msg("pushing synced local image to local registry")

	index, err := storageCommon.GetIndex(tempImageStore, repo, registry.log)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).
			Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("repo", repo).
			Msg("failed to get repo index from temp sync dir")

		return err
	}

	seen := &[]godigest.Digest{}

	for _, desc := range index.Manifests {
		reference := GetDescriptorReference(desc)

		if err := registry.copyManifest(repo, desc, reference, tempImageStore, seen); err != nil {
			if errors.Is(err, zerr.ErrImageLintAnnotations) {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("failed to upload manifest because of missing annotations")

				return nil
			}

			return err
		}
	}

	return nil
}

func (registry *DestinationRegistry) CleanupImage(imageReference ref.Ref, repo string) error {
	var err error

	dir := strings.TrimSuffix(imageReference.Path, repo)
	if _, err = os.Stat(dir); err == nil {
		if err := os.RemoveAll(strings.TrimSuffix(imageReference.Path, repo)); err != nil {
			registry.log.Error().Err(err).Msg("failed to cleanup image from temp storage")

			return err
		}
	}

	return nil
}

func (registry *DestinationRegistry) copyManifest(repo string, desc ispec.Descriptor,
	reference string, tempImageStore storageTypes.ImageStore, seen *[]godigest.Digest,
) error {
	var err error

	// seen
	if common.Contains(*seen, desc.Digest) {
		return nil
	}

	*seen = append(*seen, desc.Digest)

	imageStore := registry.storeController.GetImageStore(repo)

	manifestContent := desc.Data
	if manifestContent == nil {
		manifestContent, _, _, err = tempImageStore.GetImageManifest(repo, reference)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("repo", repo).Str("reference", reference).
				Msg("failed to get manifest from temporary sync dir")

			return err
		}
	}

	// is image manifest
	switch desc.MediaType {
	case ispec.MediaTypeImageManifest, mediatype.Docker2Manifest:
		var manifest ispec.Manifest

		if err := json.Unmarshal(manifestContent, &manifest); err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).
				Msg("invalid JSON")

			return err
		}

		for _, blob := range manifest.Layers {
			if storageCommon.IsNonDistributable(blob.MediaType) {
				continue
			}

			err := registry.copyBlob(repo, blob.Digest, blob.MediaType, tempImageStore)
			if err != nil {
				return err
			}
		}

		err := registry.copyBlob(repo, manifest.Config.Digest, manifest.Config.MediaType, tempImageStore)
		if err != nil {
			return err
		}

		digest, _, err := imageStore.PutImageManifest(repo, reference,
			desc.MediaType, manifestContent)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Msg("couldn't upload manifest")

			return err
		}

		if registry.metaDB != nil {
			err = meta.SetImageMetaFromInput(context.Background(), repo, reference, desc.MediaType,
				digest, manifestContent, imageStore, registry.metaDB, registry.log)
			if err != nil {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Msg("couldn't set metadata from input")

				return err
			}

			registry.log.Debug().Str("repo", repo).Str("reference", reference).Msg("successfully set metadata for image")
		}

	case ispec.MediaTypeImageIndex, mediatype.Docker2ManifestList:
		// is image index
		var indexManifest ispec.Index

		if err := json.Unmarshal(manifestContent, &indexManifest); err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).
				Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).
				Msg("invalid JSON")

			return err
		}

		filteredManifests := []ispec.Descriptor{}

		for _, manifest := range indexManifest.Manifests {
			reference := GetDescriptorReference(manifest)

			platform := platforms.Format(*manifest.Platform)
			if _, ok := registry.desiredPlatforms[platform]; !ok && len(registry.desiredPlatforms) > 0 {
				registry.log.Debug().Str("repo", repo).Str("reference", reference).Str("platform", platform).
					Msg("manifest not uploaded because platform is not on the desired list")

				continue
			}

			filteredManifests = append(filteredManifests, manifest)

			manifestBuf, err := tempImageStore.GetBlobContent(repo, manifest.Digest)
			if err != nil {
				registry.log.Error().Str("errorType", common.TypeOf(err)).
					Err(err).Str("dir", path.Join(tempImageStore.RootDir(), repo)).Str("digest", manifest.Digest.String()).
					Msg("failed find manifest which is part of an image index")

				return err
			}

			manifest.Data = manifestBuf

			if err := registry.copyManifest(repo, manifest, reference,
				tempImageStore, seen); err != nil {
				if errors.Is(err, zerr.ErrImageLintAnnotations) {
					registry.log.Error().Str("errorType", common.TypeOf(err)).
						Err(err).Msg("failed to upload manifest because of missing annotations")

					return nil
				}

				return err
			}
		}

		if len(filteredManifests) != len(indexManifest.Manifests) {
			/*
				The idea is to create a new partial index manifest that
				contains only desired platforms, and which is annotated for the Zot,
				so that it knows it does not deal with a "complete" manifest.

				The reason behind this idea is as follow.

				To not get all the platforms on syncing, the easiest way is to filter
				them out when copying. The regclient keeps them in the manifest index
				however. But keeping them in the manifest index will fail validation
				on putting into storage. And without putting into storage this manifest
				cannot be served from cache on subsequent requests. So manifest must
				be put there.

				It seems the only two options for doing so are to either disable
				validation or put a copy of the manifest with only selected platforms.
				Validation seems important, especially there seems no reason for
				the just copied platform-specific manifests to not undergoe this
				process. Also skipping the validation seems more complicated for it
				requires more changes in Zot as a registry.

				That is why second approach is tried out here. Manifests list is
				modified here, by replacing it with only the platforms that were copied,
				so that the entire manifest index passes validation. This step is what
				creates a new partial index manifest.

				However, filtering out manifests changes the manifest index digest,
				and hence it still would not be served from the cache due to failing
				on comparison to the upstream registry's digest (in the step
				that checks if image can be skipped on syncing).

				Hence in addition, original digest gets preserved in the
				`dev.zotregistry.image.original-digest` annotation for later comparisons.
				It is to be used instead of the new digest of the partial index manifest.
				This annotation is also what indicates the manifest is not the extact
				index manifest as the one served by the upstream registry.
			*/

			indexManifest.Manifests = filteredManifests

			if indexManifest.Annotations == nil {
				indexManifest.Annotations = map[string]string{}
			}

			indexManifest.Annotations[constants.OriginalDigestAnnotation] = desc.Digest.String()

			newManifestContent, err := json.Marshal(indexManifest)
			if err != nil {
				registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).Str("repo", repo).
					Str("reference", reference).Msg("failed to marshal updated index manifest")
				return err
			}

			manifestContent = newManifestContent
		}

		_, _, err := imageStore.PutImageManifest(repo, reference, desc.MediaType, manifestContent)
		if err != nil {
			registry.log.Error().Str("errorType", common.TypeOf(err)).Str("repo", repo).Str("reference", reference).
				Err(err).Msg("failed to upload manifest")

			return err
		}

		if registry.metaDB != nil {
			err = meta.SetImageMetaFromInput(context.Background(), repo, reference, desc.MediaType,
				desc.Digest, manifestContent, imageStore, registry.metaDB, registry.log)
			if err != nil {
				return fmt.Errorf("metaDB: failed to set metadata for image '%s %s': %w", repo, reference, err)
			}

			registry.log.Debug().Str("repo", repo).Str("reference", reference).
				Msg("metaDB: successfully set metadata for image")
		}
	}

	return nil
}

// Copy a blob from one image store to another image store.
func (registry *DestinationRegistry) copyBlob(repo string, blobDigest godigest.Digest, blobMediaType string,
	tempImageStore storageTypes.ImageStore,
) error {
	imageStore := registry.storeController.GetImageStore(repo)
	if found, _, _ := imageStore.CheckBlob(repo, blobDigest); found {
		// Blob is already at destination, nothing to do
		return nil
	}

	blobReadCloser, _, err := tempImageStore.GetBlob(repo, blobDigest, blobMediaType)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("dir", path.Join(tempImageStore.RootDir(), repo)).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't read blob")

		return err
	}
	defer blobReadCloser.Close()

	_, _, err = imageStore.FullBlobUpload(repo, blobReadCloser, blobDigest)
	if err != nil {
		registry.log.Error().Str("errorType", common.TypeOf(err)).Err(err).
			Str("blob digest", blobDigest.String()).Str("media type", blobMediaType).
			Msg("couldn't upload blob")
	}

	return err
}

// use only with local imageReferences.
func getImageStoreFromImageReference(repo string, imageReference ref.Ref, log log.Logger) storageTypes.ImageStore {
	sessionRootDir := strings.TrimSuffix(imageReference.Path, repo)

	return getImageStore(sessionRootDir, log)
}

func getImageStore(rootDir string, log log.Logger) storageTypes.ImageStore {
	metrics := monitoring.NewMetricsServer(false, log)

	return local.NewImageStore(rootDir, false, false, log, metrics, nil, nil, nil, nil)
}
