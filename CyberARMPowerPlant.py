import ThreatStatisticsSingle,ThreatPrioritization,Utitilities,ProjectConfigFile
import ThreatActionToSecurityControl,CyberARMEngine
###################################################################################### GLobal Variables ############################################################
threat_threatAction_asset = {}
asset_name_list = []
prob_threat_action_threat = {}
prob_threat_threat_action = {}
prob_threat_threat_action_alternative = {}
prob_threat = {}
risk_threat = []
risk_threat_action = []
threat_threat_action_possible_pair = {}
security_control_list = []
security_control_version_to_id = {}
threat_action_list = []
threat_action_name_to_id = {}
threat_list = []
threat_name_to_id = {}
###################################################################################### End GLobal Variables ############################################################

###################################################################################### Inputs #######################################################################
asset_enterprise_list = [['database',[500000,500000,500000]],['laptop',[100000,100000,100000]]]
enterprise_asset_list_given = []
##################################################################################### End of Inputs #################################################################

def init_power_plant():
    for asset in asset_enterprise_list:
        asset_name = asset[0]
        if asset_name not in enterprise_asset_list_given:
            enterprise_asset_list_given.append(asset_name)
    ProjectConfigFile.init_conf()

if __name__=="__main__":
    print "The Power Plant has started"
    init_power_plant()
    ThreatStatisticsSingle.find_threat_statistics_all(threat_threatAction_asset,asset_name_list,threat_threat_action_possible_pair)
    # Utitilities.printAssetList(asset_name_list)
    # # Utitilities.printNumberStatisticsThreatThreatAction(threat_threatAction_asset)
    # # print "Asset Statistics %s" % (threat_threatAction_asset)
    # # print "asset list %s" % (asset_name_list)
    #
    # ################################ Threat Prioritization ####################################################################
    ThreatPrioritization.threat_prioritization_main(prob_threat,prob_threat_threat_action,prob_threat_threat_action_alternative,prob_threat_action_threat,risk_threat_action,risk_threat,threat_threatAction_asset,asset_enterprise_list)
    # # print "Threat Statistics %s" % (prob_threat_action_threat)
    #
    # ######################################################### Check the output ##############################################################################
    # # Utitilities.printAllStatistics(prob_threat,threat_threatAction_asset,prob_threat_action_threat,threat_threat_action_possible_pair)
    # Utitilities.printAllStatisticsGivenAssets(prob_threat, threat_threatAction_asset, prob_threat_action_threat,threat_threat_action_possible_pair,enterprise_asset_list_given)
    # # Utitilities.printNumberStatisticsThreatThreatActionWithProb(prob_threat,threat_threatAction_asset,prob_threat_action_threat)
    # # Utitilities.printThreatThreatActionStatistics(threat_threatAction_asset,prob_threat_threat_action)
    # # Utitilities.printThreatImpact()
    # # Utitilities.printRiskThreatThreatAction(risk_threat_action,risk_threat,enterprise_asset_list_given)
    # # Utitilities.printKillChainPhases(enterprise_asset_list_given)
    #
    # ########################################################## List of Security Controls, Threat Action and Mappings ##########################################
    ThreatActionToSecurityControl.parseAllScAndTAFiles(security_control_list,security_control_version_to_id,prob_threat_action_threat,threat_action_list,threat_action_name_to_id,risk_threat,threat_list,threat_name_to_id,enterprise_asset_list_given)
    # # Utitilities.printSecurityControls(security_control_list,security_control_version_to_id)
    # # Utitilities.printThreatActionList(threat_action_list,threat_action_name_to_id)
    # # Utitilities.printSecurityControlThreatmapping(security_control_list,security_control_version_to_id,threat_action_list)
    # # Utitilities.printThreatSecurityControlMapping(threat_action_list,threat_action_name_to_id,security_control_list,risk_threat_action,enterprise_asset_list_given)
    CyberARMEngine.select_security_controls(security_control_list,threat_action_list,threat_action_name_to_id,risk_threat_action,asset_enterprise_list,threat_list,threat_name_to_id)
    #
