package opsgenie

import (
	"context"
	"fmt"
	"github.com/opsgenie/opsgenie-go-sdk-v2/alert"
	"github.com/opsgenie/opsgenie-go-sdk-v2/og"
	"github.com/opsgenie/opsgenie-go-sdk-v2/policy"
	"strconv"

	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	ogClient "github.com/opsgenie/opsgenie-go-sdk-v2/client"
	"github.com/opsgenie/opsgenie-go-sdk-v2/service"
)

func resourceOpsGenieServiceIncidentRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceOpsGenieServiceIncidentRuleCreate,
		Read:   handleNonExistentResource(resourceOpsGenieServiceIncidentRuleRead),
		Update: resourceOpsGenieServiceIncidentRuleUpdate,
		Delete: resourceOpsGenieServiceIncidentRuleDelete,
		Importer: &schema.ResourceImporter{
			State: func(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				idParts := strings.Split(d.Id(), "/")
				if len(idParts) != 2 || idParts[0] == "" || idParts[1] == "" {
					return nil, fmt.Errorf("Unexpected format of ID (%q), expected team_id/notification_policy_id", d.Id())
				}
				d.Set("team_id", idParts[0])
				d.SetId(idParts[1])
				return []*schema.ResourceData{d}, nil
			},
		},
		Schema: map[string]*schema.Schema{
			"service_id": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringLenBetween(1, 130),
			},
			"incident_rule": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"condition_match_type": {
							Type:         schema.TypeString,
							Optional:     true,
							Default:      "match-all",
							ValidateFunc: validation.StringInSlice([]string{"match-all", "match-any-condition", "match-all-conditions"}, false),
						},
						"conditions": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"field": {
										Type:     schema.TypeString,
										Required: true,
										ValidateFunc: validation.StringInSlice([]string{
											"message", "description", "tags",
											"extra-properties", "recipients", "teams", "priority",
										}, false),
									},
									"operation": {
										Type:     schema.TypeString,
										Required: true,
										ValidateFunc: validation.StringInSlice([]string{
											"matches", "contains", "starts-with", "ends-with", "equals", "contains-key",
											"contains-value", "greater-than", "less-than", "is-empty", "equals-ignore-whitespace",
										}, false),
									},
									"not": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "Indicates behaviour of the given operation. Default value is false",
										Default:     false,
									},
									"expected_value": {
										Type:         schema.TypeString,
										Optional:     true,
										Description:  "User defined value that will be compared with alert field according to the operation. Default value is empty string",
										ValidateFunc: validation.StringLenBetween(1, 15000),
									},
								},
							},
						},
						"incident_properties": {
							Type:     schema.TypeList,
							Required: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"message": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringLenBetween(1, 130),
									},
									"tags": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"details": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"description": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validation.StringLenBetween(1, 10000),
									},
									"priority": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validation.StringInSlice([]string{"P1", "P2", "P3", "P4", "P5"}, false),
									},
									"stakeholder_properties": {
										Type:     schema.TypeList,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"enable": {
													Type:     schema.TypeBool,
													Optional: true,
													Default:  true,
												},
												"message": {
													Type:     schema.TypeString,
													Required: true,
												},
												"description": {
													Type:         schema.TypeString,
													Optional:     true,
													ValidateFunc: validation.StringLenBetween(1, 15000),
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func resourceOpsGenieServiceIncidentRuleCreate(d *schema.ResourceData, meta interface{}) error {
	client, err := service.NewClient(meta.(*OpsgenieClient).client.Config)
	if err != nil {
		return err
	}

	service_id := d.Get("service_id").(string)
	createRequest := &service.CreateIncidentRuleRequest{
		ServiceId: service_id,
	}
	createRequest.ConditionMatchType, createRequest.Conditions = expandOpsGenieServiceIncidentRuleRequestConditions(d)
	createRequest.IncidentProperties = expandOpsGenieServiceIncidentRuleRequestIncidentProperties(d)

	log.Printf("[INFO] Creating OpsGenie Service Incident Rule for service '%s'", d.Get("service_id").(string))
	result, err := client.CreateIncidentRule(context.Background(), createRequest)
	if err != nil {
		return err
	}

	d.SetId(result.Id)

	return nil
	//return resourceOpsGenieServiceIncidentRuleRead(d, meta)
}

func resourceOpsGenieServiceIncidentRuleRead(d *schema.ResourceData, meta interface{}) error {
	client, err := service.NewClient(meta.(*OpsgenieClient).client.Config)
	if err != nil {
		return err
	}
	service_id := d.Get("service_id").(string)
	incident_rule_id := d.ID()

	log.Printf("[INFO] Reading OpsGenie Service Incident Rule for service '%s'", service_id)

	incident_rule_res, err := client.GetIncidentRules(context.Background(), &service.GetIncidentRuleRequest{
		ServiceId: service_id,
	})
	if err != nil {
		x := err.(*ogClient.ApiError)
		if x.StatusCode == 404 {
			log.Printf("[WARN] Removing Service Incident Rule because it's gone %s", name)
			d.SetId("")
			return nil
		}
	}

	for _, v := range incident_rule_res.IncidentRule {
		if v.Id == incident_rule_id {

		}

	}
	d.Set("name", policyRes.Name)
	d.Set("enabled", policyRes.Enabled)
	d.Set("policy_description", policyRes.PolicyDescription)

	d.Set("message", policyRes.Message)
	d.Set("continue_policy", policyRes.Continue)
	d.Set("alias", policyRes.Alias)
	d.Set("alert_description", policyRes.AlertDescription)
	d.Set("entity", policyRes.Entity)
	d.Set("source", policyRes.Source)
	d.Set("ignore_original_actions", policyRes.IgnoreOriginalActions)
	d.Set("actions", policyRes.Actions)
	d.Set("ignore_original_details", policyRes.IgnoreOriginalDetails)
	d.Set("details", policyRes.Details)
	d.Set("ignore_original_responders", policyRes.IgnoreOriginalResponders)
	d.Set("ignore_original_tags", policyRes.IgnoreOriginalTags)
	d.Set("tags", policyRes.Tags)

	if policyRes.Responders != nil {
		d.Set("responders", flattenOpsGenieServiceIncidentRuleResponders(policyRes.Responders))
	} else {
		d.Set("responders", nil)
	}

	if policyRes.MainFields.Filter != nil {
		d.Set("filter", flattenOpsGenieServiceIncidentRuleFilter(policyRes.MainFields.Filter))
	} else {
		d.Set("filter", nil)
	}

	if policyRes.MainFields.TimeRestriction != nil {
		log.Printf("[DEBUG] 'policy.MainFields.TimeRestriction' is not 'nil'.")
		d.Set("time_restriction", flattenOpsgenieServiceIncidentRuleTimeRestriction(policyRes.MainFields.TimeRestriction))
	} else {
		log.Printf("[DEBUG] 'policy.MainFields.TimeRestriction' is 'nil'.")
		d.Set("time_restriction", nil)
	}

	return nil
}

func resourceOpsGenieServiceIncidentRuleUpdate(d *schema.ResourceData, meta interface{}) error {
	client, err := policy.NewClient(meta.(*OpsgenieClient).client.Config)
	if err != nil {
		return err
	}

	message := d.Get("message").(string)
	continue_policy := d.Get("continue_policy").(bool)
	alias := d.Get("alias").(string)
	alert_description := d.Get("alert_description").(string)
	entity := d.Get("entity").(string)
	source := d.Get("source").(string)
	ignore_original_actions := d.Get("ignore_original_actions").(bool)
	ignore_original_details := d.Get("ignore_original_details").(bool)
	ignore_original_responders := d.Get("ignore_original_responders").(bool)
	ignore_original_tags := d.Get("ignore_original_tags").(bool)
	priority := d.Get("priority").(string)

	updateRequest := &policy.UpdateIncidentRuleRequest{
		Id:                       d.Id(),
		MainFields:               *expandOpsGenieServiceIncidentRuleRequestMainFields(d),
		Message:                  message,
		Continue:                 &continue_policy,
		Alias:                    alias,
		AlertDescription:         alert_description,
		Entity:                   entity,
		Source:                   source,
		IgnoreOriginalDetails:    &ignore_original_actions,
		IgnoreOriginalActions:    &ignore_original_details,
		IgnoreOriginalResponders: &ignore_original_responders,
		IgnoreOriginalTags:       &ignore_original_tags,
		Priority:                 alert.Priority(priority),
	}

	if len(d.Get("responders").([]interface{})) > 0 {
		updateRequest.Responders = expandOpsGenieServiceIncidentRuleResponders(d)
	}

	if len(d.Get("actions").([]interface{})) > 0 {
		updateRequest.Actions = flattenOpsgenieServiceIncidentRuleActions(d)
	}

	if len(d.Get("details").([]interface{})) > 0 {
		updateRequest.Details = flattenOpsgenieServiceIncidentRuleDetailsUpdate(d)
	}

	if len(d.Get("tags").([]interface{})) > 0 {
		updateRequest.Tags = flattenOpsgenieServiceIncidentRuleTags(d)
	}

	log.Printf("[INFO] Updating Alert Policy '%s'", d.Get("name").(string))
	_, err = client.UpdateIncidentRule(context.Background(), updateRequest)
	if err != nil {
		return err
	}

	return nil
}

func resourceOpsGenieServiceIncidentRuleDelete(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[INFO] Deleting OpsGenie Alert Policy '%s'", d.Get("name").(string))
	client, err := policy.NewClient(meta.(*OpsgenieClient).client.Config)
	if err != nil {
		return err
	}
	deleteRequest := &policy.DeletePolicyRequest{
		Id:     d.Id(),
		TeamId: d.Get("team_id").(string),
		Type:   "alert",
	}

	_, err = client.DeletePolicy(context.Background(), deleteRequest)
	if err != nil {
		return err
	}
	return nil
}

func expandOpsGenieServiceIncidentRuleRequestConditions(d *schema.ResourceData) (og.ConditionMatchType, []og.Condition) {

	incident_rule := d.Get("incident_rule").(map[string]interface{})
	input := incident_rule["conditions"].([]interface{})

	condition_match_type := og.ConditionMatchType(incident_rule["condition_match_type"].(string))
	conditions := make([]og.Condition, 0, len(input))
	condition := og.Condition{}
	if input == nil {
		return condition_match_type, conditions
	}

	for _, v := range input {
		config := v.(map[string]interface{})
		not_value := config["not"].(bool)
		order := config["order"].(int)
		condition.Field = og.ConditionFieldType(config["field"].(string))
		condition.Operation = og.ConditionOperation(config["operation"].(string))
		condition.Key = config["key"].(string)
		condition.IsNot = &not_value
		condition.ExpectedValue = config["expected_value"].(string)
		condition.Order = &order
		conditions = append(conditions, condition)
	}

	return condition_match_type, conditions
}

func expandOpsGenieServiceIncidentRuleRequestIncidentProperties(d *schema.ResourceData) []og.Condition {

	incident_rule := d.Get("incident_rule").(map[string]interface{})
	input := incident_rule["incident_properties"].([]interface{})

	incident_properties := service.IncidentProperties{}

	for _, v := range input {
		config := v.(map[string]interface{})
		incident_properties.Message = config["message"].(string)

		if len(config["tags"].([]interface{})) > 0 {
			incident_properties.Tags = flattenOpsgenieServiceIncidentRuleRequestTags(config)
		}
		if len(config["details"].([]interface{})) > 0 {
			incident_properties.Details = flattenOpsgenieServiceIncidentRuleRequestDetails(config)
		}

		incident_properties.Description = config["description"].(string)
		incident_properties.Priority = alert.Priority(config["priority"].(string))
		incident_properties.StakeholderProperties = expandOpsGenieServiceIncidentRuleRequestStakeholderProperties(config["description"].([]interface{}))
	}

}

func expandOpsGenieServiceIncidentRuleRequestStakeholderProperties(input []interface{}) service.StakeholderProperties {

	stakeholder_properties := service.StakeholderProperties{}
	if input == nil {
		return stakeholder_properties
	}

	for _, v := range input {
		config := v.(map[string]interface{})
		enable := config["enable"].(bool)
		stakeholder_properties.Enable = &enable
		stakeholder_properties.Message = config["message"].(string)
		stakeholder_properties.Description = config["description"].(string)
	}

	return stakeholder_properties
}

func flattenOpsgenieServiceIncidentRuleRequestTags(input_map map[string]interface{}) []string {
	input := input_map.Get("tags").(*schema.Set)
	tags := make([]string, len(input.List()))
	if input == nil {
		return tags
	}

	for k, v := range input.List() {
		tags[k] = v.(string)
	}
	return tags
}

func flattenOpsgenieServiceIncidentRuleRequestDetails(input_map map[string]interface{}) map[string]string {
	input := input_map.Get("details").(*schema.Set)
	details := make(map[string]string)

	if input == nil {
		return details
	}

	for k, v := range input.List() {
		details[k] = v.(string)
	}
	return details
}
