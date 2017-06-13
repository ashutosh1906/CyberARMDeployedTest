class Threat(object):
    def __init__(self,ids,name):
        self.primary_key = ids
        self.threat_name = name
        self.asset_threat_action = []
        self.asset_threat_action_prob = []
        self.threat_action_id_to_place_map = {}
        self.number_threat_action = 0
        self.threat_impact_asset = []
        self.global_asset_threat_action = []
        self.global_asset_threat_action_prob = []
        self.global_threat_action_id_to_place_map = []
        self.global_number_threat_action = 0

    def clearApplicableThreatActions(self):
        self.threat_action_id_to_place_map.clear()
        del self.asset_threat_action[:]
        del self.asset_threat_action_prob[:]
        self.number_threat_action = 0

    def addThreatActionsAsset(self,threat_action_id):
        self.asset_threat_action.append(threat_action_id)
        self.threat_action_id_to_place_map[threat_action_id] = self.number_threat_action
        self.number_threat_action += 1

    def addThreatImpact(self,risk_threat):
        for i in range(len(risk_threat)):
            if self.threat_name in risk_threat[i].keys():
                self.threat_impact_asset.append(risk_threat[i][self.threat_name])
            else:
                self.threat_impact_asset.append(0)

    def createAssetThreatAction(self,threat_action_id_list_for_specific_asset,asset_name,threat_action_list):
        self.clearApplicableThreatActions()
        for threat_action_id in threat_action_id_list_for_specific_asset:
            if self.threat_name in threat_action_list[threat_action_id].prob_given_threat_asset[asset_name].keys():
                self.asset_threat_action.append(threat_action_id)
                self.asset_threat_action_prob.append(threat_action_list[threat_action_id].prob_given_threat_asset[asset_name][self.threat_name])
                self.threat_action_id_to_place_map[threat_action_id] = self.number_threat_action
                self.number_threat_action += 1

    def globalCreateAssetThreatAction(self,threat_action_id_list_for_asset,asset_enterprise_list,threat_action_list):
        if len(self.global_asset_threat_action) > 0:
            return
        for index in range(len(asset_enterprise_list)):
            asset_name = asset_enterprise_list[index][0]
            self.global_asset_threat_action.append([])
            self.global_asset_threat_action_prob.append([])
            self.global_number_threat_action = 0
            self.global_threat_action_id_to_place_map.append({})
            for threat_action_id in threat_action_id_list_for_asset[index]:
                # print ":(:((::( %s"%(threat_action_id)
                if self.threat_name in threat_action_list[threat_action_id].prob_given_threat_asset[asset_name].keys():
                    self.global_asset_threat_action[index].append(threat_action_id)
                    self.global_asset_threat_action_prob[index].append(threat_action_list[threat_action_id].prob_given_threat_asset[asset_name][self.threat_name])
                    self.global_threat_action_id_to_place_map[index][threat_action_id] = self.global_number_threat_action
                    self.global_number_threat_action += 1


    def printProperties(self):
        print "\nID : %s Name : %s" % (self.primary_key,self.threat_name)
        print "Threat Impact %s" % (self.threat_impact_asset)
        print "Threat Action ------->"
        for i in range(len(self.asset_threat_action)):
            print "                          Threat Action ID : %s Prob : %s" % (self.asset_threat_action[i],self.asset_threat_action_prob[i])
        print "                          %s" % (self.asset_threat_action)
        print "                          %s" % (self.asset_threat_action_prob)


    def printGlobalProperties(self):
        print "\nThreat ID: %s, Name: %s" % (self.primary_key,self.threat_name)
        for index in range(len(self.global_asset_threat_action)):
            print "_________ For Asset Index %s" % (index)
            print "                       Threat Action %s" % (self.global_asset_threat_action[index])
            print "                       Threat Action Prob %s" % (self.global_asset_threat_action_prob[index])
            print "                       Place of Threat Action %s" % (self.global_threat_action_id_to_place_map[index])