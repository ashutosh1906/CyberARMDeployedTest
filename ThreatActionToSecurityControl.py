import SecurityControl,ThreatAction,Threat
import ProjectConfigFile,Utitilities
SECURITY_CONTROL_FILE = 'SecurityControls.csv'
THREAT_ACTION_SECURITY_CONTROL_FILE = 'ThreatActionSecurityControlNew.csv'
SECURITY_CONTROL_FILE_PARSER_CHARACTER = ';'
THREAT_ACTION_SECURITY_CONTROL_FILE_PARSER_CHARACTER = ';'

def security_controls_list_builder(security_control_list,security_control_version_to_id):
    sc_file = open(SECURITY_CONTROL_FILE,'r+')
    start_index = 0
    for line in sc_file:
        line = line.replace('\n','')
        line = line.lower()
        line = line.split(SECURITY_CONTROL_FILE_PARSER_CHARACTER)
        security_control_list.append(SecurityControl.SecurityControl(start_index,line[0],line[1],line[2],line[3],line[4]))
        security_control_version_to_id[line[0]] = start_index
        start_index += 1
    sc_file.close()

def threat_action_security_controls_builder(security_control_version_to_id,security_control_list,threat_action_list,threat_action_name_to_id):
    ta_sc_file = open(THREAT_ACTION_SECURITY_CONTROL_FILE,'r+')
    for line in ta_sc_file:
        line = line.replace('\n','')
        # print "Error Line %s" % (line)
        line = line.split(THREAT_ACTION_SECURITY_CONTROL_FILE_PARSER_CHARACTER)
        threat_action_name = line[0].lower().strip()
        security_control_version = line[1]
        effectiveness = float(line[2])
        sec_control_obj = security_control_list[security_control_version_to_id[security_control_version]]
        if threat_action_name not in threat_action_name_to_id.keys():
            # print "Skip Threat Action Name %s" % (threat_action_name)
            continue
        threat_action_obj = threat_action_list[threat_action_name_to_id[threat_action_name]]
        sec_control_obj.addThreatAction(threat_action_obj.primary_key,effectiveness)
        threat_action_obj.addSecurityControl(sec_control_obj.primary_key)
    ta_sc_file.close()

def threat_action_builder(prob_threat_action_threat,threat_action_list,threat_action_name_to_id,enterprise_asset_list_given):
    start_index = 0
    for asset in enterprise_asset_list_given:
        for threat in prob_threat_action_threat[asset].keys():
            for threat_action in prob_threat_action_threat[asset][threat].keys():
                if threat_action == ProjectConfigFile.THREAT_ACTION_UNKNOWN_TAG:
                    continue
                if threat_action not in threat_action_name_to_id.keys():
                    threat_action_name_to_id[threat_action] = start_index
                    threat_action_list.append(ThreatAction.ThreatAction(start_index,threat_action))
                    threat_action_list[start_index].setProbThreatAction(prob_threat_action_threat,enterprise_asset_list_given)
                    start_index += 1

def threat_builder(risk_threat,threat_list,threat_name_to_id):
    # print "Risk %s" % (risk_threat)
    threat_index = 0
    for i in range(len(risk_threat)):
        for threat in risk_threat[i].keys():
            if threat not in threat_name_to_id.keys():
                threat_name_to_id[threat] = threat_index
                threat_list.append(Threat.Threat(threat_index,threat))
                threat_list[threat_index].clearApplicableThreatActions()
                threat_list[threat_index].addThreatImpact(risk_threat)
                threat_index += 1
    # Utitilities.printThreat(threat_list,threat_name_to_id)

def parseAllScAndTAFiles(security_control_list,security_control_version_to_id,prob_threat_action_threat,threat_action_list,threat_action_name_to_id,risk_threat,threat_list,threat_name_to_id,enterprise_asset_list_given):
    security_controls_list_builder(security_control_list,security_control_version_to_id)
    threat_action_builder(prob_threat_action_threat,threat_action_list,threat_action_name_to_id,enterprise_asset_list_given)
    threat_action_security_controls_builder(security_control_version_to_id,security_control_list,threat_action_list,threat_action_name_to_id)
    threat_builder(risk_threat,threat_list,threat_name_to_id,)

