#import <Foundation/Foundation.h>
#import <CoreServices/LSApplicationProxy.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/boot_info.h>
#import <libjailbreak/launchd.h>
#import "trustcache.h"
#import "spawn_wrapper.h"
#import "server.h"
#include <libarchive/archive.h>
#include <libarchive/archive_entry.h>

static int
copy_data(struct archive *ar, struct archive *aw)
{
	int r;
	const void *buff;
	size_t size;
	la_int64_t offset;

	for (;;) {
		r = archive_read_data_block(ar, &buff, &size, &offset);
		if (r == ARCHIVE_EOF)
			return (ARCHIVE_OK);
		if (r < ARCHIVE_OK)
			return (r);
		r = archive_write_data_block(aw, buff, size, offset);
		if (r < ARCHIVE_OK) {
			fprintf(stderr, "%s\n", archive_error_string(aw));
			return (r);
		}
	}
}

int extract(NSString* fileToExtract, NSString* extractionPath)
{
	struct archive *a;
	struct archive *ext;
	struct archive_entry *entry;
	int flags;
	int r;

	/* Select which attributes we want to restore. */
	flags = ARCHIVE_EXTRACT_TIME;
	flags |= ARCHIVE_EXTRACT_PERM;
	flags |= ARCHIVE_EXTRACT_ACL;
	flags |= ARCHIVE_EXTRACT_FFLAGS;

	a = archive_read_new();
	archive_read_support_format_all(a);
	archive_read_support_filter_all(a);
	ext = archive_write_disk_new();
	archive_write_disk_set_options(ext, flags);
	archive_write_disk_set_standard_lookup(ext);
	if ((r = archive_read_open_filename(a, fileToExtract.fileSystemRepresentation, 10240)))
			return 1;
	for (;;) {
			r = archive_read_next_header(a, &entry);
			if (r == ARCHIVE_EOF)
					break;
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(a));
			if (r < ARCHIVE_WARN)
					return 1;
			
			NSString* currentFile = [NSString stringWithUTF8String:archive_entry_pathname(entry)];
			NSString* fullOutputPath = [extractionPath stringByAppendingPathComponent:currentFile];
			//printf("extracting %@ to %@\n", currentFile, fullOutputPath);
			archive_entry_set_pathname(entry, fullOutputPath.fileSystemRepresentation);
			
			r = archive_write_header(ext, entry);
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(ext));
			else if (archive_entry_size(entry) > 0) {
					r = copy_data(a, ext);
					if (r < ARCHIVE_OK)
							fprintf(stderr, "%s\n", archive_error_string(ext));
					if (r < ARCHIVE_WARN)
							return 1;
			}
			r = archive_write_finish_entry(ext);
			if (r < ARCHIVE_OK)
					fprintf(stderr, "%s\n", archive_error_string(ext));
			if (r < ARCHIVE_WARN)
					return 1;
	}
	archive_read_close(a);
	archive_read_free(a);
	archive_write_close(ext);
	archive_write_free(ext);
	
	return 0;
}

NSString *trollStoreRootHelperPath(void)
{
	LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.TrollStore"];
	return [appProxy.bundleURL.path stringByAppendingPathComponent:@"trollstorehelper"];
}


#define CS_CDHASH_LEN 20

typedef uint8_t cdhash_t[CS_CDHASH_LEN];

typedef struct trustcache_entry_v1
{
    cdhash_t hash;
    uint8_t hash_type;
    uint8_t flags;
} __attribute__((__packed__)) trustcache_entry_v1;

typedef struct s_trustcache_file_v1
{
    uint32_t version;
    uuid_t uuid;
    uint32_t length;
    trustcache_entry_v1 entries[];
} __attribute__((__packed__)) trustcache_file_v1;

void _trustcache_file_init(trustcache_file_v1 *file)
{
    memset(file, 0, sizeof(*file));
    file->version = 1;
    uuid_generate(file->uuid);
}
int _trustcache_file_sort_entry_comparator_v1(const void * vp1, const void * vp2)
{
    trustcache_entry_v1* tc1 = (trustcache_entry_v1*)vp1;
    trustcache_entry_v1* tc2 = (trustcache_entry_v1*)vp2;
    return memcmp(tc1->hash, tc2->hash, sizeof(cdhash_t));
}
void _trustcache_file_sort(trustcache_file_v1 *file)
{
    qsort(file->entries, file->length, sizeof(trustcache_entry_v1), _trustcache_file_sort_entry_comparator_v1);
}
int trustcache_file_build_from_cdhashes(cdhash_t *CDHashes, uint32_t CDHashCount, trustcache_file_v1 **tcOut)
{
    if (!CDHashes || CDHashCount == 0 || !tcOut) return -1;

    size_t tcSize = sizeof(trustcache_file_v1) + (sizeof(trustcache_entry_v1) * CDHashCount);
    trustcache_file_v1 *file = malloc(tcSize);
    _trustcache_file_init(file);

    file->length = CDHashCount;
    for (uint32_t i = 0; i < CDHashCount; i++) {
        memcpy(file->entries[i].hash, CDHashes[i], sizeof(cdhash_t));
        file->entries[i].hash_type = 2;
        file->entries[i].flags = 0;
    }
    _trustcache_file_sort(file);

    *tcOut = file;
    return 0;
}

int ensure_randomized_cdhash(const char* inputPath, void* cdhashOut);

int basebinUpdateFromTar(NSString *basebinPath, bool rebootWhenDone)
{
	LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.Dopamine.roothide"];
	if (appProxy) {
		NSString *executablePath = [appProxy.bundleURL.path stringByAppendingPathComponent:appProxy.bundleExecutable];
		if (executablePath) {
			int prepRet = spawn(executablePath, @[@"prepare_jbupdate"]);
			if (prepRet != 0) {
				JBLogDebug("WARNING: jbupdate preparation failed");
				return 100;
			}
		}
	}

	uint64_t existingTCKaddr = bootInfo_getUInt64(@"basebin_trustcache_kaddr");
	uint64_t existingTCLength = kread32(existingTCKaddr + offsetof(trustcache_page, file.length));
	uint64_t existingTCSize = sizeof(trustcache_page) + (sizeof(trustcache_entry) * existingTCLength);

	NSString *tmpExtractionPath = [NSTemporaryDirectory() stringByAppendingString:[NSUUID UUID].UUIDString];
	int extractRet = extract(basebinPath, tmpExtractionPath);
	if (extractRet != 0) {
		[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
		return 1;
	}

	NSString *tmpBasebinPath = [tmpExtractionPath stringByAppendingPathComponent:@"basebin"];
	if (![[NSFileManager defaultManager] fileExistsAtPath:tmpBasebinPath]) {
		[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
		return 2;
	}

	// NSString *newTrustcachePath = [tmpBasebinPath stringByAppendingPathComponent:@"basebin.tc"];
	// if (![[NSFileManager defaultManager] fileExistsAtPath:newTrustcachePath]) {
	// 	[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
	// 	return 3;
	// }
	
	cdhash_t* basebins_cdhashes=NULL;
    uint32_t basebins_cdhashesCount=0;
    
    NSDirectoryEnumerator<NSURL *> *directoryEnumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:tmpBasebinPath] includingPropertiesForKeys:nil options:0 errorHandler:nil];
                                             
    for(NSURL* fileURL in directoryEnumerator)
    {
        cdhash_t cdhash={0};
        if(ensure_randomized_cdhash(fileURL.path.fileSystemRepresentation, cdhash) == 0) {
            basebins_cdhashes = realloc(basebins_cdhashes, (basebins_cdhashesCount+1) * sizeof(cdhash_t));
            memcpy(&basebins_cdhashes[basebins_cdhashesCount], cdhash, sizeof(cdhash_t));
            basebins_cdhashesCount++;
        }
    }
    
    trustcache_file_v1 *basebinTcFile = NULL;
    int r = trustcache_file_build_from_cdhashes(basebins_cdhashes, basebins_cdhashesCount, &basebinTcFile);
    
    free(basebins_cdhashes);
    
    NSData* tcData = [NSData dataWithBytes:basebinTcFile length:(sizeof(trustcache_file_v1)+sizeof(trustcache_entry_v1)*basebinTcFile->length)];
    
    free(basebinTcFile);

	// uint64_t newTCKaddr = staticTrustCacheUploadFileAtPath(newTrustcachePath, NULL);
	uint64_t newTCKaddr = staticTrustCacheUploadFile((trustcache_file *)tcData.bytes, tcData.length, NULL);
	if (!newTCKaddr) {
		[[NSFileManager defaultManager] removeItemAtPath:tmpExtractionPath error:nil];
		return 4;
	}

	bootInfo_setObject(@"basebin_trustcache_kaddr", @(newTCKaddr));

	NSString *idownloaddEnabledPath = jbrootPath(@"/basebin/LaunchDaemons/com.opa334.idownloadd.plist");
	NSString *idownloaddDisabledPath = jbrootPath(@"/basebin/LaunchDaemons/Disabled/com.opa334.idownloadd.plist");
	BOOL iDownloadWasEnabled = [[NSFileManager defaultManager] fileExistsAtPath:idownloaddEnabledPath];

	// Copy new basebin over old basebin
	NSArray *basebinItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:tmpBasebinPath error:nil];
	for (NSString *basebinItem in basebinItems) {
		@autoreleasepool {
			NSString *oldBasebinPath = [jbrootPath(@"/basebin") stringByAppendingPathComponent:basebinItem];
			NSString *newBasebinPath = [tmpBasebinPath stringByAppendingPathComponent:basebinItem];
			if ([[NSFileManager defaultManager] fileExistsAtPath:oldBasebinPath]) {
				[[NSFileManager defaultManager] removeItemAtPath:oldBasebinPath error:nil];
			}
			[[NSFileManager defaultManager] copyItemAtPath:newBasebinPath toPath:oldBasebinPath error:nil];
		}
	}
	patchBaseBinLaunchDaemonPlists();

	if (iDownloadWasEnabled) {
		[[NSFileManager defaultManager] moveItemAtPath:idownloaddDisabledPath toPath:idownloaddEnabledPath error:nil];
	}

	// Update systemhook.dylib on bind mount
	NSString* systemhookFilePath = [NSString stringWithFormat:@"%@/systemhook-%@.dylib", jbrootPath(@"/basebin"), bootInfo_getObject(@"JBRAND")];
	if ([[NSFileManager defaultManager] fileExistsAtPath:systemhookFilePath]) {
		[[NSFileManager defaultManager] removeItemAtPath:systemhookFilePath error:nil];
	}
	[[NSFileManager defaultManager] copyItemAtPath:jbrootPath(@"/basebin/systemhook.dylib") toPath:systemhookFilePath error:nil];

	trustCacheListRemove(existingTCKaddr);

	// there is a non zero chance that the kernel is in the process of reading the
	// trustcache page even after we removed it, so we wait a second before freeing it
	sleep(1);

	kfree(existingTCKaddr, existingTCSize);

	if (rebootWhenDone) {
		safeRebootUserspace();
	}

	return 0;
}

int jbUpdateFromTIPA(NSString *tipaPath, bool rebootWhenDone)
{
	NSString *tsRootHelperPath = trollStoreRootHelperPath();
	if (!tsRootHelperPath) return 1;
	int installRet = spawn(tsRootHelperPath, @[@"install", tipaPath]);
	if (installRet != 0) return 2;

	LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:@"com.opa334.Dopamine.roothide"];
	int bbRet = basebinUpdateFromTar([appProxy.bundleURL.path stringByAppendingPathComponent:@"basebin.tar"], rebootWhenDone);
	if (bbRet != 0) return 2 + bbRet;
	return 0;
}