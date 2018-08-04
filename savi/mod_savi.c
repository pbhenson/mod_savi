/*
 * Sophos SAVI Virus-scanning Module for Apache HTTP Server
 *
 * Paul B. Henson <henson@acm.org>
 *
 * Copyright (c) 2001-2002 Paul B. Henson -- see COPYRIGHT file for details
 *
 */

/* MODULE-DEFINITION-START
 * Name: savi
 * ConfigStart

   CFLAGS="$CFLAGS -I`pwd`"
   LIBS="$LIBS -lsavi"

 * ConfigEnd
 * MODULE-DEFINITION-END
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "sav_if/csavi2c.h"

typedef struct server_config_struct {
  char *ide_location;
  char *tmpdir;
  int do_full_sweep;
  int dynamic_decompression;
  int full_macro_sweep;
  int ole2_handling;
  int ignore_template_bit;
  int vba3_handling;
  int vba5_handling;
  int of95_decrypt_handling;
  int help_handling;
  int decompress_vba5;
  int do_emulation;
  int pe_handling;
  int xf_handling;
  int pm97_handling;
  int ppt_embd_handling;
  int project_handling;
  int zip_decompression;
  int arj_decompression;
  int rar_decompression;
  int uue_decompression;
  int gzip_decompression;
  int tar_decompression;
  int cmz_decompression;
  int hqx_decompression;
  int mbin_decompression;
  int loopback_enabled;
  int max_recursion_depth;
  int lha_decompression;
  int sfx_handling;
  int mscabinet_handling;
  int tnef_handling;
  int mscompress_handling;
  int delete_all_macros;
  int vbe;
  int exec_file_disinfection;
  int visio_file_handling;
} server_config_rec;

typedef struct dir_config_struct {
  int active;
} dir_config_rec;

static CISavi2 *savi = NULL;

server_config_rec server_config = {
  NULL, /* ide_location */
  NULL, /* tmpdir */
  1, /* do_full_sweep */
  1, /* dynamic_decompression */
  1, /* full_macro_sweep */
  1, /* ole2_handling */
  1, /* ignore_template_bit */
  1, /* vba3_handling */
  1, /* vba5_handling */
  0, /* of95_decrypt_handling */
  1, /* help_handling */
  1, /* decompress_vba5 */
  1, /* do_emulation */
  1, /* pe_handling */
  1, /* xf_handling */
  1, /* pm97_handling */
  1, /* ppt_embd_handling */
  1, /* project_handling */
  1, /* zip_decompression */
  1, /* arj_decompression */
  1, /* rar_decompression */
  1, /* uue_decompression */
  1, /* gzip_decompression */
  1, /* tar_decompression */
  1, /* cmz_decompression */
  1, /* hqx_decompression */
  1, /* mbin_decompression */
  0, /* loopback_enabled */
  16, /* max_recursion_depth */
  1, /* lha_decompression */
  1, /* sfx_handling */
  1, /* mscabinet_handling */
  1, /* tnef_handling */
  1, /* mscompress_handling */
  0, /* delete_all_macros */
  0, /* vbe */
  0, /* exec_file_disinfection */
  1  /* visio_file_handling */
};


static void *create_server_config(pool *p, server_rec *s) {
  return ap_pcalloc (p, sizeof(server_config_rec));
}

static void *merge_server_configs(pool *p, void *basev, void *addv) {
  server_config_rec *new = (server_config_rec*)ap_pcalloc(p, sizeof(server_config_rec));
  server_config_rec *base = (server_config_rec *)basev;
  server_config_rec *add = (server_config_rec *)addv;
  
  return new;
}

static const char *set_ide_location(cmd_parms *cmd, void *dv, char *word1) {
  server_config.ide_location = (word1) ? ap_pstrdup(cmd->pool, word1) : NULL;
  return NULL;
}

static const char *set_tmpdir(cmd_parms *cmd, void *dv, char *word1) {
  server_config.tmpdir = (word1) ? ap_pstrdup(cmd->pool, word1) : NULL;
  return NULL;
}

static const char *set_do_full_sweep(cmd_parms *cmd, void *dv, int bool) {
  server_config.do_full_sweep = bool;
  return NULL;
}

static const char *set_dynamic_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.dynamic_decompression = bool;
  return NULL;
}

static const char *set_full_macro_sweep(cmd_parms *cmd, void *dv, int bool) {
  server_config.full_macro_sweep = bool;
  return NULL;
}

static const char *set_ole2_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.ole2_handling = bool;
  return NULL;
}

static const char *set_ignore_template_bit(cmd_parms *cmd, void *dv, int bool) {
  server_config.ignore_template_bit = bool;
  return NULL;
}

static const char *set_vba3_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.vba3_handling = bool;
  return NULL;
}

static const char *set_vba5_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.vba5_handling = bool;
  return NULL;
}

static const char *set_of95_decrypt_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.of95_decrypt_handling = bool;
  return NULL;
}

static const char *set_help_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.help_handling = bool;
  return NULL;
}

static const char *set_decompress_vba5(cmd_parms *cmd, void *dv, int bool) {
  server_config.decompress_vba5 = bool;
  return NULL;
}

static const char *set_do_emulation(cmd_parms *cmd, void *dv, int bool) {
  server_config.do_emulation = bool;
  return NULL;
}

static const char *set_pe_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.pe_handling = bool;
  return NULL;
}

static const char *set_xf_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.xf_handling = bool;
  return NULL;
}

static const char *set_pm97_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.pm97_handling = bool;
  return NULL;
}

static const char *set_ppt_embd_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.ppt_embd_handling = bool;
  return NULL;
}

static const char *set_project_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.project_handling = bool;
  return NULL;
}

static const char *set_zip_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.zip_decompression = bool;
  return NULL;
}

static const char *set_arj_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.arj_decompression = bool;
  return NULL;
}

static const char *set_rar_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.rar_decompression = bool;
  return NULL;
}

static const char *set_uue_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.uue_decompression = bool;
  return NULL;
}

static const char *set_gzip_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.gzip_decompression = bool;
  return NULL;
}

static const char *set_tar_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.tar_decompression = bool;
  return NULL;
}

static const char *set_cmz_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.cmz_decompression = bool;
  return NULL;
}

static const char *set_hqx_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.hqx_decompression = bool;
  return NULL;
}

static const char *set_mbin_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.mbin_decompression = bool;
  return NULL;
}

static const char *set_loopback_enabled(cmd_parms *cmd, void *dv, int bool) {
  server_config.loopback_enabled = bool;
  return NULL;
}

static const char *set_max_recursion_depth(cmd_parms *cmd, void *dv, char *word1) {
  int depth = word1 ? atoi(word1) : -1;

  if (depth < 0 || depth > 128)
    return "mod_savi: invalid SaviMaxRecursionDepth";
  
  server_config.max_recursion_depth = depth;
  return NULL;
}

static const char *set_lha_decompression(cmd_parms *cmd, void *dv, int bool) {
  server_config.lha_decompression = bool;
  return NULL;
}

static const char *set_sfx_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.sfx_handling = bool;
  return NULL;
}

static const char *set_mscabinet_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.mscabinet_handling = bool;
  return NULL;
}

static const char *set_tnef_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.tnef_handling = bool;
  return NULL;
}

static const char *set_mscompress_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.mscompress_handling = bool;
  return NULL;
}

static const char *set_delete_all_macros(cmd_parms *cmd, void *dv, int bool) {
  server_config.delete_all_macros = bool;
  return NULL;
}

static const char *set_vbe(cmd_parms *cmd, void *dv, int bool) {
  server_config.vbe = bool;
  return NULL;
}

static const char *set_exec_file_disinfection(cmd_parms *cmd, void *dv, int bool) {
  server_config.exec_file_disinfection = bool;
  return NULL;
}

static const char *set_visio_file_handling(cmd_parms *cmd, void *dv, int bool) {
  server_config.visio_file_handling = bool;
  return NULL;
}

static void *create_dir_config(pool *p, char *d) {
  dir_config_rec *new = (dir_config_rec*)ap_pcalloc(p, sizeof(dir_config_rec));
  return new;
}

static void *merge_dir_configs(pool *p, void *basev, void *addv) {
  
  dir_config_rec *new = (dir_config_rec*)ap_pcalloc(p, sizeof(dir_config_rec));
  dir_config_rec *base = (dir_config_rec *)basev;
  dir_config_rec *add = (dir_config_rec *)addv;

  new->active = add->active;
  return new;
}


static command_rec cmds[] = {
  { "SaviEnable", ap_set_flag_slot, (void *) XtOffsetOf(dir_config_rec, active), OR_AUTHCFG, FLAG,
    "Activate Sophos Anti-Virus Scanning in this Directory" },

  { "SaviIDELocation", set_ide_location, NULL, RSRC_CONF, TAKE1,
    "" },

  { "SaviTmpDir", set_tmpdir, NULL, RSRC_CONF, TAKE1,
    "" },

  { "SaviDoFullSweep", set_do_full_sweep, NULL, RSRC_CONF, FLAG,
    "" },
  
  { "SaviDynamicCompression", set_dynamic_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviFullMacroSweep", set_full_macro_sweep, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviOLE2Handling", set_ole2_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviIgnoreTemplateBit", set_ignore_template_bit, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviVBA3Handling", set_vba3_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviVBA5Handling", set_vba5_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviOf95DecryptHandling", set_of95_decrypt_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviHelpHandling", set_help_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviDecompressVBA5", set_decompress_vba5, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviDoEmulation", set_do_emulation, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviPEHandling", set_pe_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviXFHandling", set_xf_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviPM97Handling", set_pm97_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviPPTEmbdHandling", set_ppt_embd_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviProjectHandling", set_project_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviZipDecompression", set_zip_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviARJDecompression", set_arj_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviRARDecompression", set_rar_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviUUEDecompression", set_uue_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviGzipDecompression", set_gzip_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviTarDecompression", set_tar_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviCMZDecompression", set_cmz_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviHQXDecompression", set_hqx_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviMbinDecompression", set_mbin_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviLoopbackEnabled", set_loopback_enabled, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviMaxRecursionDepth", set_max_recursion_depth, NULL, RSRC_CONF, TAKE1,
    "" },

  { "SaviLHADecompression", set_lha_decompression, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviSFXHandling", set_sfx_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviMSCabinetHandling", set_mscabinet_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviTNEFHandling", set_tnef_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviMSCompressHandling", set_mscompress_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviDeleteAllMacros", set_delete_all_macros, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviVBE", set_vbe, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviExecFileDisinfection", set_exec_file_disinfection, NULL, RSRC_CONF, FLAG,
    "" },

  { "SaviVisioFileHandling", set_visio_file_handling, NULL, RSRC_CONF, FLAG,
    "" },

  { NULL }
};


module savi_module;


static int scan(request_rec *r) {
  
  dir_config_rec *dir_config = (dir_config_rec *)ap_get_module_config(r->per_dir_config, &savi_module);

  char *savi_header;
  HRESULT status;
  
  if (!dir_config->active)
    return DECLINED;

  if (!savi) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "savi.scan - savi not initialized, declining request");
    savi_header = ap_pstrdup(r->pool, "error;savi not initialized");
  }
  else if (! S_ISREG(r->finfo.st_mode)) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "savi.scan - attempt to scan non-file %s", r->filename);
    savi_header = ap_pstrdup(r->pool, "error;attempt to scan non-file");
  }
  else {
    
    CIEnumSweepResults *sweep_results;

    status = savi->pVtbl->SweepFile(savi, r->filename, (REFIID)&SOPHOS_IID_ENUM_SWEEPRESULTS, (void **)&sweep_results);
    if (status == SOPHOS_S_OK) {
      savi_header = ap_pstrdup(r->pool, "clean");
    }
    else if (status == SOPHOS_SAVI2_ERROR_VIRUSPRESENT) {
      
      CISweepResults *virus_info;
	  
      savi_header = ap_pstrdup(r->pool, "infected");
	  
      sweep_results->pVtbl->Reset(sweep_results);
	  
      while (sweep_results->pVtbl->Next(sweep_results, 1, (void **)&virus_info, NULL) == SOPHOS_S_OK) {
	char virus_name[128];
	      
	if (virus_info->pVtbl->GetVirusName(virus_info, 128, virus_name, NULL) == SOPHOS_S_OK) {
	  savi_header = ap_pstrcat(r->pool, savi_header, ";", virus_name, NULL);
	}
	virus_info->pVtbl->Release(virus_info);
      }
    }
    else {
      char error_string[128];

      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "savi.scan - SweepFile failed: %x", SOPHOS_CODE(status));

      snprintf(error_string, 128, "error;SweepFile failed - %x", SOPHOS_CODE(status));
      error_string[127] = '\0';
      savi_header = ap_pstrdup(r->pool, error_string); 
    }

    sweep_results->pVtbl->Release(sweep_results);
  }

  ap_table_set(r->headers_out, "X-SAVI-Status", savi_header);
  return OK;
}


static void cleanup(void *arg) {
  
  savi->pVtbl->Terminate(savi);
  savi->pVtbl->Release(savi);
}


static void set_config_u16(server_rec *s, char *name, int value) {

  char value_string[128];
  HRESULT status;

  snprintf(value_string, 128, "%d", value);
  value_string[127] = '\0';

  status = savi->pVtbl->SetConfigValue(savi, name, SOPHOS_TYPE_U16, value_string);
  if (SOPHOS_FAILED(status)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s, "savi.set_config_u16: SetConfigValue (%s=%s) failed - %x",
		 name, value_string, SOPHOS_CODE(status));
  }
}


static void set_config_u32(server_rec *s, char *name, int value) {

  char value_string[128];
  HRESULT status;

  snprintf(value_string, 128, "%d", value);
  value_string[127] = '\0';

  status = savi->pVtbl->SetConfigValue(savi, name, SOPHOS_TYPE_U32, value_string);
  if (SOPHOS_FAILED(status)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s, "savi.set_config_u32: SetConfigValue (%s=%s) failed - %x",
		 name, value_string, SOPHOS_CODE(status));
  }
}


static void initialize(server_rec *s, pool *p) {
  
  CISweepClassFactory2 *factory;
  HRESULT status;
  U32 version;
  char version_string[128];
  U32 virus_count;
  CIEnumIDEDetails *ide_list;
  SYSTEMTIME release_date;
  
  if (server_config.ide_location)
    putenv(ap_pstrcat(p, "SAV_IDE=", server_config.ide_location, NULL));

  if (server_config.tmpdir)
    putenv(ap_pstrcat(p, "SAV_TMP=", server_config.tmpdir, NULL));

  status = DllGetClassObject((REFIID)&SOPHOS_CLSID_SAVI2, (REFIID)&SOPHOS_IID_CLASSFACTORY2, (void **)&factory);
  if (SOPHOS_FAILED(status)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s, "savi.initialize: DllGetClassObject failed - %x", SOPHOS_CODE(status));
    return;
  }
  
  status = factory->pVtbl->CreateInstance(factory, NULL, &SOPHOS_IID_SAVI2, (void **)&savi);
  if (SOPHOS_FAILED(status)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s, "savi.initialize: CreateInstance failed - %x", SOPHOS_CODE(status));
    savi = NULL;
    return;
  }

  factory->pVtbl->Release(factory);

  status = savi->pVtbl->InitialiseWithMoniker(savi, "mod_savi");
  if (SOPHOS_FAILED(status)) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s, "savi.initialize: InitialiseWithMoniker failed - %x", SOPHOS_CODE(status));
    savi->pVtbl->Release(savi);
    savi = NULL;
    return;
  }

  status = savi->pVtbl->GetVirusEngineVersion(savi, &version, version_string, 128, NULL, &virus_count, NULL,
				       (REFIID)&SOPHOS_IID_ENUM_IDEDETAILS, (void **)&ide_list);
  if (SOPHOS_SUCCEEDED(status)) {
    CIIDEDetails *ide_details;
    char ide_name[128];

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s, "savi.initialize: Sophos version %d.%d (%s) - %d viruses detectable",
		 version >> 16, version & 0x0000ffff, version_string, virus_count); 

    ide_list->pVtbl->Reset(ide_list);

    while (ide_list->pVtbl->Next(ide_list, 1, (void **)&ide_details, NULL) == SOPHOS_S_OK) {
	
      if (ide_details->pVtbl->GetName(ide_details, 128, ide_name, NULL) == SOPHOS_S_OK) {
	    
	if (ide_details->pVtbl->GetDate(ide_details, &release_date) == SOPHOS_S_OK)
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s, "savi.initialize: IDE %s - released %d/%d/%d",
		       ide_name, release_date.wMonth, release_date.wDay, release_date.wYear);
	else
	  ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, s, "savi.initialize: IDE %s", ide_name);
      }

      ide_details->pVtbl->Release(ide_details);
    }

    ide_list->pVtbl->Release(ide_list);
  }
  else {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, s, "savi.initialize: GetVirusEngineVersion failed - %d", status);
  }
  
  set_config_u32(s, SOPHOS_DO_FULL_SWEEP, server_config.do_full_sweep);
  set_config_u32(s, SOPHOS_DYNAMIC_DECOMPRESSION, server_config.dynamic_decompression);
  set_config_u32(s, SOPHOS_FULL_MACRO_SWEEP, server_config.full_macro_sweep);
  set_config_u32(s, SOPHOS_OLE2_HANDLING, server_config.ole2_handling);
  set_config_u32(s, SOPHOS_IGNORE_TEMPLATE_BIT, server_config.ignore_template_bit);
  set_config_u32(s, SOPHOS_VBA3_HANDLING, server_config.vba3_handling);
  set_config_u32(s, SOPHOS_VBA5_HANDLING, server_config.vba5_handling);
  set_config_u32(s, SOPHOS_OF95_DECRYPT_HANDLING, server_config.of95_decrypt_handling);
  set_config_u32(s, SOPHOS_HELP_HANDLING, server_config.help_handling);
  set_config_u32(s, SOPHOS_DECOMPRESS_VBA5, server_config.decompress_vba5);
  set_config_u32(s, SOPHOS_DO_EMULATION, server_config.do_emulation);
  set_config_u32(s, SOPHOS_PE_HANDLING, server_config.pe_handling);
  set_config_u32(s, SOPHOS_XF_HANDLING, server_config.xf_handling);
  set_config_u32(s, SOPHOS_PM97_HANDLING, server_config.pm97_handling);
  set_config_u32(s, SOPHOS_PPT_EMBD_HANDLING, server_config.ppt_embd_handling);
  set_config_u32(s, SOPHOS_PROJECT_HANDLING, server_config.project_handling);
  set_config_u32(s, SOPHOS_ZIP_DECOMPRESSION, server_config.zip_decompression);
  set_config_u32(s, SOPHOS_ARJ_DECOMPRESSION, server_config.arj_decompression);
  set_config_u32(s, SOPHOS_RAR_DECOMPRESSION, server_config.rar_decompression);
  set_config_u32(s, SOPHOS_UUE_DECOMPRESSION, server_config.uue_decompression);
  set_config_u32(s, SOPHOS_GZIP_DECOMPRESSION, server_config.gzip_decompression);
  set_config_u32(s, SOPHOS_TAR_DECOMPRESSION, server_config.tar_decompression);
  set_config_u32(s, SOPHOS_CMZ_DECOMPRESSION, server_config.cmz_decompression);
/*  set_config_u32(s, SOPHOS_HQX_DECOMPRESSION, server_config.hqx_decompression); */
/*  set_config_u32(s, SOPHOS_MBIN_DECOMPRESSION, server_config.mbin_decompression); */
  set_config_u32(s, SOPHOS_LOOPBACK_ENABLED, server_config.loopback_enabled);
  set_config_u16(s, SOPHOS_MAX_RECURSION_DEPTH, server_config.max_recursion_depth);
  set_config_u32(s, SOPHOS_LHA_DECOMPRESSION, server_config.lha_decompression);
  set_config_u32(s, SOPHOS_SFX_HANDLING, server_config.sfx_handling);
  set_config_u32(s, SOPHOS_MSCABINET_HANDLING, server_config.mscabinet_handling);
  set_config_u32(s, SOPHOS_TNEF_HANDLING, server_config.tnef_handling);
  set_config_u32(s, SOPHOS_MSCOMPRESS_HANDLING, server_config.mscompress_handling);
  set_config_u32(s, SOPHOS_DELETE_ALL_MACROS, server_config.delete_all_macros);
  set_config_u32(s, SOPHOS_VBE, server_config.vbe);
  set_config_u32(s, SOPHOS_EXEC_FILE_DISINFECTION, server_config.exec_file_disinfection);
  set_config_u32(s, SOPHOS_VISIO_FILE_HANDLING, server_config.visio_file_handling);
    
  ap_register_cleanup(p, NULL, cleanup, ap_null_cleanup);
}


module savi_module = {
  STANDARD_MODULE_STUFF,
  initialize,	        /* initializer */
  create_dir_config,    /* dir config creater */
  merge_dir_configs,   	/* dir merger --- default is to override */
  create_server_config,	/* server config */
  merge_server_configs,	/* merge server config */
  cmds,		        /* command table */
  NULL,			/* handlers */
  NULL,			/* filename translation */
  NULL,	                /* check_user_id */
  NULL,	                /* check auth */
  NULL,			/* check access */
  NULL,			/* type_checker */
  scan,			/* fixups */
  NULL,	        	/* logger */
  NULL,                 /* [3] header parser */
  NULL,                 /* process initializer */
  NULL,                 /* process exit/cleanup */
  NULL                  /* [1] post read_request handling */
};
