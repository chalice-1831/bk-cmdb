/*
 * Tencent is pleased to support the open source community by making 蓝鲸 available.
 * Copyright (C) 2017-2018 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * http://opensource.org/licenses/MIT
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"configcenter/src/common"
	"configcenter/src/common/blog"
	lang "configcenter/src/common/language"
	"configcenter/src/common/mapstr"
	"configcenter/src/common/metadata"
	"configcenter/src/common/querybuilder"
	"configcenter/src/common/util"

	"github.com/rentiansheng/xlsx"
)

// GetHostData get host data from excel
func (lgc *Logics) GetHostData(appID int64, hostIDStr string, hostFields []string, header http.Header) ([]mapstr.MapStr, error) {
	rid := util.GetHTTPCCRequestID(header)
	hostInfo := make([]mapstr.MapStr, 0)
	sHostCond := make(map[string]interface{})

	hostIDArr := strings.Split(hostIDStr, ",")
	iHostIDArr := make([]int64, 0)
	for _, j := range hostIDArr {
		hostID, err := strconv.ParseInt(j, 10, 64)
		if err != nil {
			return nil, err
		}
		iHostIDArr = append(iHostIDArr, hostID)
	}
	if -1 != appID {
		sHostCond[common.BKAppIDField] = appID
		sHostCond["ip"] = make(map[string]interface{})
		sHostCond["condition"] = make([]interface{}, 0)
		sHostCond["page"] = make(map[string]interface{})
	} else {
		sHostCond[common.BKAppIDField] = -1
		sHostCond["ip"] = make(map[string]interface{})
	}
	condArr := make([]interface{}, 0)

	// host condition
	condition := make(map[string]interface{})
	hostCondArr := make([]interface{}, 0)
	hostCond := make(map[string]interface{})
	hostCond["field"] = common.BKHostIDField
	hostCond["operator"] = common.BKDBIN
	hostCond["value"] = iHostIDArr
	hostCondArr = append(hostCondArr, hostCond)
	condition[common.BKObjIDField] = common.BKInnerObjIDHost
	condition["fields"] = make([]string, 0)
	if len(hostFields) > 0 {
		condition["fields"] = hostFields
	}
	condition["condition"] = hostCondArr
	condArr = append(condArr, condition)

	// biz condition
	condition = make(map[string]interface{})
	condition[common.BKObjIDField] = common.BKInnerObjIDApp
	condition["fields"] = make([]interface{}, 0)
	condition["condition"] = make([]interface{}, 0)
	condArr = append(condArr, condition)

	// set condition
	condition = make(map[string]interface{})
	condition[common.BKObjIDField] = common.BKInnerObjIDSet
	condition["fields"] = make([]interface{}, 0)
	condition["condition"] = make([]interface{}, 0)
	condArr = append(condArr, condition)

	// module condition
	condition = make(map[string]interface{})
	condition[common.BKObjIDField] = common.BKInnerObjIDModule
	condition["fields"] = make([]interface{}, 0)
	condition["condition"] = make([]interface{}, 0)
	condArr = append(condArr, condition)

	sHostCond["condition"] = condArr
	sHostCond["page"] = make(map[string]interface{})

	result, err := lgc.Engine.CoreAPI.ApiServer().GetHostData(context.Background(), header, sHostCond)
	if nil != err {
		blog.Errorf("GetHostData failed, search condition: %+v, err: %+v, rid: %s", sHostCond, err, rid)
		return hostInfo, err
	}

	if !result.Result {
		blog.Errorf("GetHostData failed, search condition: %+v, result: %+v, rid: %s", sHostCond, result, rid)
		return nil, lgc.CCErr.CreateDefaultCCErrorIf(util.GetLanguage(header)).New(result.Code, result.ErrMsg)
	}

	return result.Data.Info, nil
}

// GetImportHosts get import hosts
// return inst array data, errmsg collection, error
func (lgc *Logics) GetImportHosts(f *xlsx.File, header http.Header, defLang lang.DefaultCCLanguageIf, modelBizID int64) (map[int]map[string]interface{}, []string, error) {
	ctx := util.NewContextFromHTTPHeader(header)

	if 0 == len(f.Sheets) {
		return nil, nil, errors.New(defLang.Language("web_excel_content_empty"))
	}
	fields, err := lgc.GetObjFieldIDs(common.BKInnerObjIDHost, nil, nil, header, modelBizID)
	if nil != err {
		return nil, nil, errors.New(defLang.Languagef("web_get_object_field_failure", err.Error()))
	}

	sheet := f.Sheets[0]
	if nil == sheet {
		return nil, nil, errors.New(defLang.Language("web_excel_sheet_not_found"))
	}

	return GetExcelData(ctx, sheet, fields, common.KvMap{"import_from": common.HostAddMethodExcel}, true, 0, defLang)
}

// ImportHosts import host info
func (lgc *Logics) ImportHosts(ctx context.Context, f *xlsx.File, header http.Header, defLang lang.DefaultCCLanguageIf,
	modelBizID int64, moduleID int64) *metadata.ResponseDataMapStr {

	rid := util.ExtractRequestIDFromContext(ctx)
	defErr := lgc.CCErr.CreateDefaultCCErrorIf(util.GetLanguage(header))

	hosts, errMsg, err := lgc.GetImportHosts(f, header, defLang, modelBizID)
	if nil != err {
		blog.Errorf("ImportHosts failed, GetImportHosts error:%s, rid: %s", err.Error(), rid)
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebFileContentFail,
				ErrMsg: defErr.Errorf(common.CCErrWebFileContentFail, err.Error()).Error(),
			},
			Data: nil,
		}
	}
	if len(errMsg) > 0 {
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebFileContentFail,
				ErrMsg: defErr.Errorf(common.CCErrWebFileContentFail, errMsg[0]).Error(),
			},
			Data: map[string]interface{}{
				"error": errMsg,
			},
		}
	}

	errMsg, err = lgc.CheckHostsAdded(ctx, header, hosts)
	if nil != err {
		blog.Errorf("ImportHosts failed,  CheckHostsAdded error:%s, rid: %s", err.Error(), rid)
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebHostCheckFail,
				ErrMsg: defErr.Errorf(common.CCErrWebHostCheckFail, err.Error()).Error(),
			},
			Data: nil,
		}
	}
	if len(errMsg) > 0 {
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebHostCheckFail,
				ErrMsg: defErr.Errorf(common.CCErrWebHostCheckFail, errMsg[0]).Error(),
			},
			Data: map[string]interface{}{
				"error": errMsg,
			},
		}
	}

	var resultErr error
	result := &metadata.ResponseDataMapStr{}
	result.BaseResp.Result = true
	result.Data = mapstr.New()
	if len(hosts) > 0 {
		params := map[string]interface{}{
			"host_info":            hosts,
			"input_type":           common.InputTypeExcel,
			common.BKModuleIDField: moduleID,
		}
		result, resultErr = lgc.CoreAPI.ApiServer().AddHostByExcel(context.Background(), header, params)
		if nil != resultErr {
			blog.Errorf("ImportHosts add host info  http request  error:%s, rid:%s", resultErr.Error(), util.GetHTTPCCRequestID(header))
			return &metadata.ResponseDataMapStr{
				BaseResp: metadata.BaseResp{
					Result: false,
					Code:   common.CCErrCommHTTPDoRequestFailed,
					ErrMsg: defErr.Error(common.CCErrCommHTTPDoRequestFailed).Error(),
				},
				Data: nil,
			}
		}
	}

	if len(f.Sheets) < 2 {
		return result
	}

	// if len(f.Sheets) >= 2, the second sheet is association data to be import
	asstInfoMap := GetAssociationExcelData(f.Sheets[1], common.HostAddMethodExcelAssociationIndexOffset)
	if len(asstInfoMap) == 0 {
		return result
	}

	asstInfoMapInput := &metadata.RequestImportAssociation{
		AssociationInfoMap: asstInfoMap,
	}
	asstResult, asstResultErr := lgc.CoreAPI.ApiServer().ImportAssociation(ctx, header, common.BKInnerObjIDHost, asstInfoMapInput)
	if nil != asstResultErr {
		blog.Errorf("ImportHosts logics http request import association error:%s, rid:%s", asstResultErr.Error(), util.GetHTTPCCRequestID(header))
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrCommHTTPDoRequestFailed,
				ErrMsg: defErr.Error(common.CCErrCommHTTPDoRequestFailed).Error(),
			},
			Data: nil,
		}
	}

	result.Data.Set("asst_error", asstResult.Data.ErrMsgMap)

	if result.Result && !asstResult.Result {
		result.BaseResp = asstResult.BaseResp
	}

	return result
}

// UpdateHosts update excel import hosts
func (lgc *Logics) UpdateHosts(ctx context.Context, f *xlsx.File, header http.Header, defLang lang.DefaultCCLanguageIf,
	modelBizID int64) *metadata.ResponseDataMapStr {

	rid := util.ExtractRequestIDFromContext(ctx)
	defErr := lgc.CCErr.CreateDefaultCCErrorIf(util.GetLanguage(header))

	hosts, errMsg, err := lgc.GetImportHosts(f, header, defLang, modelBizID)
	if nil != err {
		blog.Errorf("ImportHost get import hosts from excel err, error:%s, rid: %s", err.Error(), rid)
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebFileContentFail,
				ErrMsg: defErr.Errorf(common.CCErrWebFileContentFail, err.Error()).Error(),
			},
			Data: nil,
		}
	}
	if 0 != len(errMsg) {
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebFileContentFail,
				ErrMsg: defErr.Errorf(common.CCErrWebFileContentFail, errMsg[0]).Error(),
			},
			Data: map[string]interface{}{
				"error": errMsg,
			},
		}
	}

	errMsg, err = lgc.CheckHostsUpdated(ctx, header, hosts)
	if nil != err {
		blog.Errorf("ImportHosts failed,  CheckHostsAdded error:%s, rid: %s", err.Error(), rid)
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebHostCheckFail,
				ErrMsg: defErr.Errorf(common.CCErrWebHostCheckFail, err.Error()).Error(),
			},
			Data: nil,
		}
	}
	if len(errMsg) > 0 {
		return &metadata.ResponseDataMapStr{
			BaseResp: metadata.BaseResp{
				Result: false,
				Code:   common.CCErrWebHostCheckFail,
				ErrMsg: defErr.Errorf(common.CCErrWebHostCheckFail, errMsg[0]).Error(),
			},
			Data: map[string]interface{}{
				"error": errMsg,
			},
		}
	}

	var resultErr error
	result := &metadata.ResponseDataMapStr{}
	result.BaseResp.Result = true
	result.Data = mapstr.New()
	if 0 != len(hosts) {
		params := map[string]interface{}{
			"host_info":  hosts,
			"input_type": common.InputTypeExcel,
		}
		result, resultErr = lgc.CoreAPI.ApiServer().UpdateHost(context.Background(), header, params)
		if nil != resultErr {
			blog.Errorf("UpdateHosts update host http request  error:%s, rid:%s", resultErr.Error(), util.GetHTTPCCRequestID(header))
			return &metadata.ResponseDataMapStr{
				BaseResp: metadata.BaseResp{
					Result: false,
					Code:   common.CCErrCommHTTPDoRequestFailed,
					ErrMsg: defErr.Error(common.CCErrCommHTTPDoRequestFailed).Error(),
				},
				Data: nil,
			}
		}
	}

	return result
}

// CheckHostsAdded check the hosts to be added
func (lgc *Logics) CheckHostsAdded(ctx context.Context, header http.Header, hostInfos map[int]map[string]interface{}) (errMsg []string, err error) {
	rid := util.ExtractRequestIDFromContext(ctx)
	ccLang := lgc.Engine.Language.CreateDefaultCCLanguageIf(util.GetLanguage(header))

	existentHosts, err := lgc.getExistHostsByInnerIPs(ctx, header, hostInfos)
	if err != nil {
		blog.Errorf("CheckHostsAdded failed, getExistHostsByInnerIPs err:%s, rid:%s", err.Error(), rid)
		return nil, err
	}

	for index, host := range hostInfos {
		if nil == host {
			continue
		}

		innerIP, ok := host[common.BKHostInnerIPField].(string)
		if ok == false || "" == innerIP {
			errMsg = append(errMsg, ccLang.Languagef("host_import_innerip_empty", index))
			continue
		}

		// check if the host exist in db
		key := generateHostCloudKey(innerIP, common.BKDefaultDirSubArea)
		if _, exist := existentHosts[key]; exist {
			errMsg = append(errMsg, ccLang.Languagef("import_host_exist_error", index, key))
			continue
		}
	}

	return errMsg, nil
}

// CheckHostsUpdated check the hosts to be updated
func (lgc *Logics) CheckHostsUpdated(ctx context.Context, header http.Header, hostInfos map[int]map[string]interface{}) (errMsg []string, err error) {
	rid := util.ExtractRequestIDFromContext(ctx)
	ccLang := lgc.Engine.Language.CreateDefaultCCLanguageIf(util.GetLanguage(header))

	existentHost, err := lgc.getExistHostsByHostIDs(ctx, header, hostInfos)
	if err != nil {
		blog.Errorf("CheckHostsUpdated failed, getExistHostsByHostIDs err:%s, rid:%s", err.Error(), rid)
		return nil, err
	}

	for index, host := range hostInfos {
		if host == nil {
			continue
		}

		hostID, ok := host[common.BKHostIDField]
		if !ok {
			blog.Errorf("CheckHostsUpdated failed, because bk_host_id field doesn't exist, innerIp: %v, rid: %v", host[common.BKHostInnerIPField], rid)
			errMsg = append(errMsg, ccLang.Languagef("import_update_host_miss_hostID", index))
			continue
		}
		hostIDVal, err := util.GetInt64ByInterface(hostID)
		if err != nil {
			errMsg = append(errMsg, ccLang.Languagef("import_update_host_hostID_not_int", index))
			continue
		}

		// check if the host exist in db
		ip, exist := existentHost[hostIDVal]
		if !exist {
			errMsg = append(errMsg, ccLang.Languagef("import_host_no_exist_error", index, hostIDVal))
			continue
		}

		excelIP := util.GetStrByInterface(host[common.BKHostInnerIPField])
		if ip != excelIP {
			errMsg = append(errMsg, ccLang.Languagef("import_host_ip_not_consistent", index, excelIP, hostIDVal, ip))
			continue
		}
	}

	return errMsg, nil
}

// generateHostCloudKey generate a cloudKey for host that is unique among clouds by appending the cloudID.
func generateHostCloudKey(ip, cloudID interface{}) string {
	return fmt.Sprintf("%v-%v", ip, cloudID)
}

// getExistHostsByInnerIPs get hosts that already in db(same bk_host_innerip host)
// return: map[hostKey]bool
func (lgc *Logics) getExistHostsByInnerIPs(ctx context.Context, header http.Header, hostInfos map[int]map[string]interface{}) (map[string]bool, error) {
	rid := util.ExtractRequestIDFromContext(ctx)
	defErr := lgc.CCErr.CreateDefaultCCErrorIf(util.GetLanguage(header))

	// step1. extract all innerIP from hostInfos
	var ipArr []string
	for _, host := range hostInfos {
		innerIP, ok := host[common.BKHostInnerIPField].(string)
		if ok && "" != innerIP {
			ipArr = append(ipArr, innerIP)
		}
	}
	if len(ipArr) == 0 {
		return make(map[string]bool), nil
	}

	// step2. query host info by innerIPs
	rules := make([]querybuilder.Rule, len(ipArr))
	for index, innerIP := range ipArr {
		innerIPArr := strings.Split(innerIP, ",")
		rules[index] = querybuilder.AtomRule{
			Field:    common.BKHostInnerIPField,
			Operator: querybuilder.OperatorIn,
			Value:    innerIPArr,
		}
	}

	option := metadata.ListHostsWithNoBizParameter{
		HostPropertyFilter: &querybuilder.QueryFilter{
			Rule: querybuilder.CombinedRule{
				Condition: querybuilder.ConditionOr,
				Rules:     rules,
			},
		},
		Fields: []string{
			common.BKHostIDField,
			common.BKHostInnerIPField,
			common.BKCloudIDField,
		},
	}
	resp, err := lgc.CoreAPI.ApiServer().ListHostWithoutApp(ctx, header, option)
	if err != nil {
		blog.Errorf(" getExistHostsByInnerIPs failed, ListHostWithoutApp err:%v, option: %d, rid: %s", err, option, rid)
		return nil, defErr.CCError(common.CCErrCommHTTPDoRequestFailed)
	}
	if resp.Code != 0 || resp.Result == false {
		blog.Errorf(" getExistHostsByInnerIPs failed, ListHostWithoutApp resp:%#v, option: %d, rid: %s", resp, option, rid)
		return nil, defErr.New(resp.Code, resp.ErrMsg)
	}

	// step3. arrange data as a map, cloudKey: hostID
	hostMap := make(map[string]bool, 0)
	for _, host := range resp.Data.Info {
		key := generateHostCloudKey(host[common.BKHostInnerIPField], host[common.BKCloudIDField])
		hostMap[key] = true
	}

	return hostMap, nil
}

// getExistHostsByHostIDs get hosts that already in db(same bk_host_id host)
// return: map[hostID]innerIP
func (lgc *Logics) getExistHostsByHostIDs(ctx context.Context, header http.Header, hostInfos map[int]map[string]interface{}) (map[int64]string, error) {
	rid := util.ExtractRequestIDFromContext(ctx)
	defErr := lgc.CCErr.CreateDefaultCCErrorIf(util.GetLanguage(header))

	// step1. extract all innerIP from hostInfos
	var hostIDs []int64
	for _, host := range hostInfos {
		if hostID, ok := host[common.BKHostIDField]; ok {
			if hostIDVal, err := util.GetInt64ByInterface(hostID); err == nil {
				hostIDs = append(hostIDs, hostIDVal)
			}
		}
	}

	if len(hostIDs) == 0 {
		return make(map[int64]string), nil
	}

	// step2. query host info by hostIDs
	rules := []querybuilder.Rule{
		querybuilder.AtomRule{
			Field:    common.BKHostIDField,
			Operator: querybuilder.OperatorIn,
			Value:    hostIDs,
		},
	}

	option := metadata.ListHostsWithNoBizParameter{
		HostPropertyFilter: &querybuilder.QueryFilter{
			Rule: querybuilder.CombinedRule{
				Condition: querybuilder.ConditionOr,
				Rules:     rules,
			},
		},
		Fields: []string{
			common.BKHostIDField,
			common.BKHostInnerIPField,
		},
	}
	resp, err := lgc.CoreAPI.ApiServer().ListHostWithoutApp(ctx, header, option)
	if err != nil {
		blog.Errorf(" getExistHostsByHostIDs failed, ListHostWithoutApp err:%v, option: %d, rid: %s", err, option, rid)
		return nil, defErr.CCError(common.CCErrCommHTTPDoRequestFailed)
	}
	if resp.Code != 0 || resp.Result == false {
		blog.Errorf(" getExistHostsByHostIDs failed, ListHostWithoutApp resp:%#v, option: %d, rid: %s", resp, option, rid)
		return nil, defErr.New(resp.Code, resp.ErrMsg)
	}

	// step3. arrange data as a map, cloudKey: hostID
	hostMap := make(map[int64]string, 0)
	for _, host := range resp.Data.Info {
		if hostID, ok := host[common.BKHostIDField]; ok {
			if hostIDVal, err := util.GetInt64ByInterface(hostID); err == nil {
				hostMap[hostIDVal] = util.GetStrByInterface(host[common.BKHostInnerIPField])
			}
		}
	}

	return hostMap, nil
}
