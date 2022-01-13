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
	"fmt"
	"strconv"
	"strings"

	"configcenter/src/common"
	"configcenter/src/common/blog"
	"configcenter/src/common/errors"
	"configcenter/src/common/http/rest"
	"configcenter/src/common/mapstr"
	meta "configcenter/src/common/metadata"
	parse "configcenter/src/common/paraparse"
	"configcenter/src/common/util"
)

type InstNameAsst struct {
	ID         string                 `json:"id"`
	ObjID      string                 `json:"bk_obj_id"`
	ObjIcon    string                 `json:"bk_obj_icon"`
	ObjectID   int64                  `json:"bk_inst_id"`
	ObjectName string                 `json:"bk_obj_name"`
	Name       string                 `json:"bk_inst_name"`
	InstInfo   map[string]interface{} `json:"inst_info,omitempty"`
}

func (lgc *Logics) getInstAsst(kit *rest.Kit, objID string, IDs []string, query *meta.QueryInput) ([]InstNameAsst, int, errors.CCError) {
	return lgc.getRawInstAsst(kit, objID, IDs, query, false)

}

func (lgc *Logics) getInstAsstDetail(kit *rest.Kit, objID string, IDs []string, query *meta.QueryInput) ([]InstNameAsst, int, errors.CCError) {
	return lgc.getRawInstAsst(kit, objID, IDs, query, true)
}

func (lgc *Logics) getRawInstAsst(kit *rest.Kit, objID string, IDs []string, query *meta.QueryInput, isDetail bool) ([]InstNameAsst, int, errors.CCError) {
	var instName, instID string
	tmpIDs := []int{}
	for _, ID := range IDs {
		if "" == strings.TrimSpace(ID) {
			continue
		}
		tmpID, err := strconv.Atoi(ID)
		if nil != err {
			blog.Errorf("getRawInstAsst get objID(%s) inst id not integer, inst id:(%+v), rid:%s", objID, IDs, kit.Rid)
			return nil, 0, kit.CCError.Errorf(common.CCErrCommInstFieldConvertFail, objID, "association id", "int", err.Error())
		}
		tmpIDs = append(tmpIDs, tmpID)
	}
	if 0 == len(tmpIDs) {
		return make([]InstNameAsst, 0), 0, nil
	}
	condition := mapstr.New()
	if nil != query.Condition {
		newCondtion, err := mapstr.NewFromInterface(query.Condition)
		if err != nil {
			blog.Errorf("getRawInstAsst get objID(%s) inst id not integer, inst id:(%+v), rid:%s", objID, IDs, kit.Rid)
			return nil, 0, kit.CCError.Errorf(common.CCErrCommInstFieldConvertFail, objID, "query condition", "map[string]interface{}", err.Error())
		}
		condition = newCondtion
	}
	input := &meta.QueryCondition{
		Fields: strings.Split(query.Fields, ","),
		Page:   meta.BasePage{Start: query.Start, Limit: query.Limit, Sort: query.Sort},
	}
	rawObjID := objID
	switch objID {
	case common.BKInnerObjIDHost:
		instName = common.BKHostInnerIPField
		instID = common.BKHostIDField
		if 0 != len(tmpIDs) {
			condition[common.BKHostIDField] = map[string]interface{}{"$in": tmpIDs}
		}
	case common.BKInnerObjIDApp:
		instName = common.BKAppNameField
		instID = common.BKAppIDField
		if 0 != len(tmpIDs) {
			condition[common.BKAppIDField] = map[string]interface{}{"$in": tmpIDs}
		}
	case common.BKInnerObjIDSet:
		instID = common.BKSetIDField
		instName = common.BKSetNameField
		query.Sort = common.BKSetIDField
		if 0 != len(tmpIDs) {
			condition[common.BKSetIDField] = map[string]interface{}{"$in": tmpIDs}
		}
	case common.BKInnerObjIDModule:
		instID = common.BKModuleIDField
		instName = common.BKModuleNameField
		query.Sort = common.BKModuleIDField
		if 0 != len(tmpIDs) {
			condition[common.BKModuleIDField] = map[string]interface{}{"$in": tmpIDs}
		}
	case common.BKInnerObjIDPlat:
		instID = common.BKCloudIDField
		instName = common.BKCloudNameField
		query.Sort = common.BKCloudIDField
		if 0 != len(tmpIDs) {
			condition[common.BKCloudIDField] = map[string]interface{}{"$in": tmpIDs}
		}
	default:
		instName = common.BKInstNameField
		instID = common.BKInstIDField
		query.Sort = common.BKInstIDField
		condition[common.BKObjIDField] = objID
		if 0 != len(tmpIDs) {
			condition[common.BKInstIDField] = map[string]interface{}{"$in": tmpIDs}
		}
		rawObjID = objID
	}
	input.Condition = condition
	rtn, err := lgc.CoreAPI.CoreService().Instance().ReadInstance(kit.Ctx, kit.Header, rawObjID, input)
	if err != nil {
		blog.Errorf("getRawInstAsst SearchObjects http do error, err:%s,objID:%s,input:%+v,rid:%s", err.Error(), objID, input, kit.Rid)
		return nil, 0, kit.CCError.Error(common.CCErrCommHTTPDoRequestFailed)
	}
	if !rtn.Result {
		blog.Errorf("getRawInstAsst SearchObjects http reponse error, err code:%d, err msg:%s,objID:%s,input:%+v,rid:%s", rtn.Code, rtn.ErrMsg, objID, input, kit.Rid)
		return nil, 0, kit.CCError.New(rtn.Code, rtn.ErrMsg)
	}

	delarry := func(s []string, i int) []string {
		s[len(s)-1], s[i] = s[i], s[len(s)-1]
		return s[:len(s)-1]
	}

	allInst := make([]InstNameAsst, 0)
	for _, info := range rtn.Data.Info {
		if val, exist := info[instName]; exist {
			inst := InstNameAsst{}
			if name, can := val.(string); can {
				inst.Name = name
				inst.ObjID = objID
				if isDetail {
					inst.InstInfo = info
				}
			}

			if dataVal, exist := info[instID]; exist {

				itemInstID, err := util.GetInt64ByInterface(dataVal)
				if nil != err {
					blog.Errorf("not found assocte object ID %s from %v, rid: %s", instID, info, kit.Rid)
					return nil, 0, fmt.Errorf("not found assocte object ID %s from %v", instID, info)
				}
				if 0 != len(IDs) {
					for idx, key := range IDs {
						if key == strconv.FormatInt(itemInstID, 10) {
							inst.ID = IDs[idx]
							inst.ObjectID, _ = util.GetInt64ByInterface(IDs[idx])
							IDs = delarry(IDs, idx)
							allInst = append(allInst, inst)
							goto next
						}
					}
				} else {
					inst.ID = strconv.FormatInt(itemInstID, 10)
					inst.ObjectID = itemInstID
					allInst = append(allInst, inst)
				}

			next:
			}
		}
	}

	// get the InstName name
	for _, ID := range IDs {
		allInst = append(allInst, InstNameAsst{ID: ID})
	}

	return allInst, rtn.Data.Count, nil
}

// SearchInstance search model instance by condition
func (lgc *Logics) SearchInstance(kit *rest.Kit, objID string, input *meta.QueryCondition) ([]mapstr.MapStr,
	errors.CCErrorCoder) {

	instanceRes, err := lgc.CoreAPI.CoreService().Instance().ReadInstance(kit.Ctx, kit.Header, objID, input)
	if err != nil {
		blog.ErrorJSON("search %s instance failed, err: %s, input: %s, rid: %s", objID, err, input, kit.Rid)
		return nil, kit.CCError.CCError(common.CCErrCommHTTPDoRequestFailed)
	}

	if err := instanceRes.CCError(); err != nil {
		blog.ErrorJSON("search %s instance failed, err: %s, query: %s, rid: %s", objID, err, input, kit.Rid)
		return nil, err
	}

	return instanceRes.Data.Info, nil
}

// GetInstIDNameInfo get instance ids and id to name map by condition
func (lgc *Logics) GetInstIDNameInfo(kit *rest.Kit, objID string, cond mapstr.MapStr) (map[int64]string, error) {
	idField := meta.GetInstIDFieldByObjID(objID)
	nameField := meta.GetInstNameFieldName(objID)

	query := &meta.QueryCondition{
		Fields:    []string{idField, nameField},
		Condition: cond,
		Page: meta.BasePage{
			Limit: common.BKNoLimit,
		},
	}

	instances, err := lgc.SearchInstance(kit, objID, query)
	if err != nil {
		return nil, err
	}

	instanceMap := make(map[int64]string)
	for _, instance := range instances {
		instanceID, err := instance.Int64(idField)
		if err != nil {
			blog.Errorf("instance %v id is invalid, err: %v, rid: %s", instance, err, kit.Rid)
			return nil, kit.CCError.CCErrorf(common.CCErrCommParamsInvalid, idField)
		}

		instanceName, err := instance.String(nameField)
		if err != nil {
			blog.Errorf("instance %v name is invalid, err: %v, rid: %s", instance, err, kit.Rid)
			return nil, kit.CCError.CCErrorf(common.CCErrCommParamsInvalid, nameField)
		}
		instanceMap[instanceID] = instanceName
	}

	return instanceMap, nil
}

// GetInstIDs get instance ids by condition items
func (lgc *Logics) GetInstIDs(kit *rest.Kit, objID string, cond []meta.ConditionItem) ([]int64, errors.CCErrorCoder) {
	if len(cond) == 0 {
		return make([]int64, 0), nil
	}

	condition := make(map[string]interface{})
	if err := parse.ParseCommonParams(cond, condition); err != nil {
		blog.ErrorJSON("parse condition item failed, err: %s, cond: %s, rid: %s", err, cond, kit.Rid)
		return nil, kit.CCError.CCErrorf(common.CCErrCommParamsInvalid, objID+"_cond")
	}

	idField := meta.GetInstIDFieldByObjID(objID)

	query := &meta.QueryCondition{
		Fields:    []string{idField},
		Condition: condition,
		Page: meta.BasePage{
			Limit: common.BKNoLimit,
		},
	}

	instances, err := lgc.SearchInstance(kit, objID, query)
	if err != nil {
		return nil, err
	}

	instanceIDs := make([]int64, 0)
	for _, instance := range instances {
		instanceID, err := instance.Int64(idField)
		if err != nil {
			blog.ErrorJSON("instance %s id is invalid, error: %s, rid: %s", instance, err, kit.Rid)
			return nil, kit.CCError.CCErrorf(common.CCErrCommParamsInvalid, idField)
		}

		if instanceID == 0 {
			continue
		}

		instanceIDs = append(instanceIDs, instanceID)
	}
	return instanceIDs, nil
}

// GetObjInstParentID return object's inst - parent_id map
func (lgc *Logics) GetObjInstParentID(kit *rest.Kit, objID string, instID int64) (int64, errors.CCErrorCoder) {

	cond := &meta.QueryCondition{
		Condition:      mapstr.MapStr{common.GetInstIDField(objID): instID},
		Fields:         []string{common.GetInstIDField(objID), common.BKParentIDField},
		DisableCounter: true,
	}
	insts, ccErr := lgc.SearchInstance(kit, objID, cond)
	if ccErr != nil {
		blog.Errorf("get child inst info failed, cond: %v, err: %v, rid: %s", cond, ccErr, kit.Rid)
		return 0, ccErr
	}

	if len(insts) != 1 {
		blog.Errorf("search instance by id[%d]，number of results isn't 1, result: %v, rid: %s", instID, insts, kit.Rid)
		return 0, kit.CCError.CCError(common.CCErrCommNotFound)
	}

	parentID, err := insts[0].Int64(common.BKParentIDField)
	if err != nil {
		blog.Errorf("get child int64 parent_id failed, inst: %v, err: %v, rid: %s", insts[0], err, kit.Rid)
		return 0, kit.CCError.CCErrorf(common.CCErrCommParamsInvalid, common.GetInstIDField(objID))
	}

	return parentID, nil
}

// GetInstIDNameInfo get instance ids and id to name map by condition
func (lgc *Logics) GetInstIDsByCond(kit *rest.Kit, objID string, cond mapstr.MapStr) ([]int64, error) {
	idField := meta.GetInstIDFieldByObjID(objID)

	query := &meta.QueryCondition{
		Fields:    []string{idField},
		Condition: cond,
		Page: meta.BasePage{
			Limit: common.BKNoLimit,
		},
	}

	instances, err := lgc.SearchInstance(kit, objID, query)
	if err != nil {
		return nil, err
	}

	instanceIDs := make([]int64, 0)
	for _, instance := range instances {
		instanceID, err := instance.Int64(idField)
		if err != nil {
			blog.Errorf("instance %v id is invalid, err: %v, rid: %s", instance, err, kit.Rid)
			return nil, err
		}
		instanceIDs = append(instanceIDs, instanceID)
	}

	return instanceIDs, nil
}

// SearchBizHostTopo search hosts with its' topo under business
// related issue:https://github.com/Tencent/bk-cmdb/issues/5891
func (lgc *Logics) SearchBizHostTopo(kit *rest.Kit, bizID int64, param *meta.ListBizHostsTopoParameter) (
	*meta.HostTopoResult, error) {

	childMap, parentMap, err := lgc.searchMainlineRelationMap(kit, bizID)
	if err != nil {
		blog.Errorf("get mainline association failed, err: %v, rid: %s", err, kit.Rid)
		return nil, err
	}

	filterIDs, err := lgc.getBizHostTopoMainlineObjectFilter(kit, param, childMap)
	if err != nil {
		blog.Errorf("get host topo mainline object filter failed, err: %v, rid: %s", err, kit.Rid)
		return nil, err
	}

	hostRelation, hostInfo, err := lgc.getHostMainlineRelation(kit, bizID, param, parentMap, filterIDs)
	if err != nil {
		blog.Errorf("get host topo mainline relation failed, err: %v, rid: %s", err, kit.Rid)
		return nil, err
	}

	if len(hostInfo) == 0 {
		return nil, nil
	}

	return lgc.findHostTopo(kit, hostRelation, childMap, parentMap, hostInfo, filterIDs)
}

func (lgc *Logics) getBizHostTopoMainlineObjectFilter(kit *rest.Kit, param *meta.ListBizHostsTopoParameter,
	objChildMap map[string]string) (map[string][]int64, error) {

	filterIDs := make(map[string][]int64)
	// if set filter or module filter is set, search them first to get ids to filter hosts
	for objID, filter := range param.MainlinePropertyFilter {
		mainlineFilter, key, err := filter.ToMgo()
		if err != nil {
			blog.Errorf("custom[%s] filter %s is invalid, key: %s, err: %s, rid: %s", objID, filter, key, err, kit.Rid)
			return nil, err
		}

		filterMainlineIDs, err := lgc.GetInstIDsByCond(kit, objID, mainlineFilter)
		if err != nil {
			blog.Errorf("get custom[%s] by filter(%s) failed, err: %s, rid: %s", objID, filter, err, kit.Rid)
			return nil, err
		}

		if len(filterMainlineIDs) == 0 {
			return nil, nil
		}

		filterIDs[objID] = filterMainlineIDs
	}

	return filterIDs, nil
}

func (lgc *Logics) searchMainlineRelationMap(kit *rest.Kit, bizID int64) (map[string]string, map[string]string, error) {
	// 获取主线模型关联关系
	cond := &meta.QueryCondition{
		Condition:      mapstr.MapStr{common.AssociationKindIDField: common.AssociationKindMainline},
		Fields:         []string{common.BKObjIDField, common.BKAsstObjIDField},
		DisableCounter: true,
	}
	mainline, err := lgc.CoreAPI.CoreService().Association().ReadModelAssociation(kit.Ctx, kit.Header, cond)
	if err != nil {
		blog.Errorf("get mainline association failed, cond: %v, err: %v, rid: %s", cond, err, kit.Rid)
		return nil, nil, err
	}

	if ccErr := mainline.CCError(); ccErr != nil {
		blog.Errorf("get mainline association failed, cond: %v, err: %v, rid: %s", cond, ccErr, kit.Rid)
		return nil, nil, err
	}

	objChildMap := make(map[string]string)
	objParentMap := make(map[string]string)
	filterIDs := make(map[string][]int64)
	filterIDs[common.BKInnerObjIDApp] = []int64{bizID}
	for _, item := range mainline.Data.Info {
		filterIDs[item.ObjectID] = make([]int64, 0)

		if item.ObjectID == common.BKInnerObjIDHost {
			continue
		}

		objChildMap[item.AsstObjID] = item.ObjectID
		objParentMap[item.ObjectID] = item.AsstObjID
	}

	return objChildMap, objParentMap, nil
}

func (lgc *Logics) getHostMainlineRelation(kit *rest.Kit, bizID int64, param *meta.ListBizHostsTopoParameter,
	parentMap map[string]string, filterIDs map[string][]int64) (map[int64]map[string][]int64,
	map[int64]map[string]interface{}, error) {

	// search all hosts
	option := &meta.ListHosts{
		BizID:              bizID,
		HostPropertyFilter: param.HostPropertyFilter,
		Fields:             append(param.Fields, common.BKHostIDField),
		Page:               param.Page,
	}
	hosts, err := lgc.CoreAPI.CoreService().Host().ListHosts(kit.Ctx, kit.Header, option)
	if err != nil {
		blog.Errorf("find host failed, err: %v, input:%#v, rid: %s", err, option, kit.Rid)
		return nil, nil, err
	}

	if len(hosts.Info) == 0 {
		return nil, nil, nil
	}

	// search all hosts' host module relations
	hostIDs := make([]int64, 0)
	hostInfo := make(map[int64]map[string]interface{})
	for _, host := range hosts.Info {
		hostID, err := util.GetInt64ByInterface(host[common.BKHostIDField])
		if err != nil {
			blog.Errorf("host: %v bk_host_id field invalid, rid: %s", host, kit.Rid)
			return nil, nil, err
		}
		hostIDs = append(hostIDs, hostID)
		hostInfo[hostID] = host
	}

	relationCond := meta.HostModuleRelationRequest{
		ApplicationID: bizID,
		HostIDArr:     hostIDs,
		Fields:        []string{common.BKSetIDField, common.BKModuleIDField, common.BKHostIDField},
	}
	relations, err := lgc.GetHostRelations(kit, relationCond)
	if err != nil {
		blog.Errorf("read host module relation failed, err: %v, input: %s, rid: %s", err, relationCond, kit.Rid)
		return nil, nil, err
	}

	totalRelation, err := lgc.buildHostRelation(kit, relations, parentMap, filterIDs)
	if err != nil {
		blog.Errorf("built host total relation failed, err: %v, rid: %s", err, kit.Rid)
		return nil, nil, err
	}

	return totalRelation, hostInfo, nil
}

func (lgc *Logics) buildHostRelation(kit *rest.Kit, relations []meta.ModuleHost, parentMap map[string]string,
	filterIDs map[string][]int64) (map[int64]map[string][]int64, error) {

	hostModule := make(map[int64][]int64, 0)
	for _, item := range relations {
		if _, exist := hostModule[item.HostID]; !exist {
			hostModule[item.HostID] = make([]int64, 0)
		}

		hostModule[item.HostID] = append(hostModule[item.HostID], item.ModuleID)
	}

	totalRelation := make(map[int64]map[string][]int64)
	for hostID, instIDs := range hostModule {
		totalRelation[hostID] = make(map[string][]int64)
		for objID := common.BKInnerObjIDModule; objID != common.BKInnerObjIDApp; objID = parentMap[objID] {
			if len(filterIDs[objID]) != 0 {
				instIDs = util.IntArrIntersection(instIDs, filterIDs[objID])
			}

			if len(instIDs) == 0 {
				delete(totalRelation, hostID)
				break
			}

			totalRelation[hostID][objID] = util.IntArrayUnique(instIDs)
			cond := &meta.QueryCondition{
				Condition: mapstr.MapStr{common.GetInstIDField(objID): mapstr.MapStr{common.BKDBIN: instIDs}},
				Fields:    []string{common.BKDefaultField, common.BKParentIDField},
			}
			rsp, err := lgc.SearchInstance(kit, objID, cond)
			if err != nil {
				blog.Errorf("search set failed, err: %v, input: %s, rid: %s", err, cond, kit.Rid)
				return nil, err
			}

			instIDs = make([]int64, 0)
			defaultValue := 0
			for _, item := range rsp {
				parentID, err := item.Int64(common.BKParentIDField)
				if err != nil {
					blog.Errorf("get object[%s] parentID failed, err: %v, rid: %s", objID, err, kit.Rid)
					return nil, err
				}
				instIDs = append(instIDs, parentID)

				if defaultFieldValue, exist := item[common.BKDefaultField]; exist {
					if defaultValue, err = util.GetIntByInterface(defaultFieldValue); err != nil {
						blog.Errorf("get instance %s default failed, err: %s, rid: %s", item, err, kit.Rid)
						return nil, err
					}
				}
			}

			if defaultValue != common.DefaultFlagDefaultValue && objID == common.BKInnerObjIDSet {
				break
			}
		}
	}

	return totalRelation, nil
}

func (lgc *Logics) findHostTopo(kit *rest.Kit, hostRelation map[int64]map[string][]int64, childMap,
	parentMap map[string]string, hostInfo map[int64]map[string]interface{}, filterIDs map[string][]int64) (
	*meta.HostTopoResult, error) {

	rsp := &meta.HostTopoResult{}
	for hostID, relation := range hostRelation {

		bizChildIDs := make([]int64, 0)
		var objID string
		for objectID := childMap[common.BKInnerObjIDApp]; len(objectID) != 0; objectID = childMap[objectID] {
			if _, exist := relation[objectID]; exist {
				bizChildIDs = relation[objectID]
				objID = objectID
				break
			}
		}
		results := make([]map[string]interface{}, 0)
		parents := make([]map[string]interface{}, 0)
		instCond := mapstr.MapStr{common.GetInstIDField(objID): mapstr.MapStr{common.BKDBIN: bizChildIDs}}
		for objectID := objID; len(objectID) != 0; objectID = childMap[objectID] {
			filter := &meta.QueryCondition{Condition: instCond}
			instanceRsp, err := lgc.SearchInstance(kit, objectID, filter)
			if err != nil {
				blog.Errorf("search inst failed, err: %s, cond:%s, rid: %s", err, instCond, kit.Rid)
				return nil, err
			}
			// already reached the deepest level, stop the loop
			if len(instanceRsp) == 0 {
				break
			}
			instIDs := make([]int64, 0)
			instances := make([]map[string]interface{}, 0)
			childInstMap := make(map[int64][]map[string]interface{})
			for _, instance := range instanceRsp {
				topoInst, instID, err := buildTopoInst(instance, objectID, childMap, kit.Rid)
				if err != nil {
					blog.Errorf("build topo inst by instance:%v failed, err: %s, rid: %s", instance, err, kit.Rid)
					return nil, err
				}
				instIDs = append(instIDs, instID)
				if len(parents) == 0 {
					results = append(results, topoInst)
				} else {
					parentID, err := instance.Int64(common.BKParentIDField)
					if err != nil {
						blog.Errorf("get instance %s parent id failed, err: %s, rid: %s", instance, err, kit.Rid)
						return nil, err
					}
					childInstMap[parentID] = append(childInstMap[parentID], topoInst)
				}
				instances = append(instances, topoInst)
			}
			// set children for parents, default sets are children of biz
			for _, parentInst := range parents {
				instID, err := util.GetInt64ByInterface(parentInst[common.GetInstIDField(parentMap[objectID])])
				if err != nil {
					blog.Errorf("get instance %s inst id type failed, err: %s, rid: %s", parentInst, err, kit.Rid)
					return nil, err
				}
				switch child := parentInst[objectID].(type) {
				case []map[string]interface{}:
					child = append(child, childInstMap[instID]...)
					parentInst[objectID] = child
				default:
					blog.Errorf("get instance %s child type failed, err: %s, rid: %s", parentInst, err, kit.Rid)
					return nil, err
				}
			}
			// set current instances as parents and generate condition for next level
			instCond = make(map[string]interface{})
			parents = instances
			instCond[common.BKInstParentStr] = map[string]interface{}{common.BKDBIN: instIDs}
			instCond[common.GetInstIDField(childMap[objectID])] = map[string]interface{}{
				common.BKDBIN: relation[childMap[objectID]],
			}
		}
		rsp.Info = append(rsp.Info, meta.HostTopo{Host: hostInfo[hostID], Topo: results})
	}

	rsp.Count = len(rsp.Info)
	return rsp, nil
}

func buildTopoInst(instance mapstr.MapStr, objectID string, childMap map[string]string, rid string) (
	map[string]interface{}, int64, error) {

	instID, err := instance.Int64(meta.GetInstIDFieldByObjID(objectID))
	if err != nil {
		blog.Errorf("get instance %s id failed, err: %s, rid: %s", instance, err, rid)
		return nil, 0, err
	}
	instName, err := instance.String(meta.GetInstNameFieldName(objectID))
	if err != nil {
		blog.Errorf("get instance %s name failed, err: %s, rid: %s", instance, err, rid)
		return nil, 0, err
	}
	topoInst := map[string]interface{}{
		common.GetInstIDField(objectID):   instID,
		common.GetInstNameField(objectID): instName,
	}

	if child, exist := childMap[objectID]; exist {
		topoInst[child] = make([]map[string]interface{}, 0)
	}

	return topoInst, instID, nil
}
