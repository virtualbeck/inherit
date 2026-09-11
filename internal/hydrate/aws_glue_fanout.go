package hydrate

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/virtualbeck/inherit/model"
)

func init() {
	registerFanout("aws_glue_catalog_database", fanoutGlueTables)
}

// glueColumns renders a []Column as columns[]/partition_keys[] entries --
// both share the exact same {name, type, comment, parameters} shape.
func glueColumns(cols []gluetypes.Column) []any {
	var out []any
	for _, col := range cols {
		cm := map[string]any{"name": aws.ToString(col.Name)}
		if v := aws.ToString(col.Type); v != "" {
			cm["type"] = v
		}
		if v := aws.ToString(col.Comment); v != "" {
			cm["comment"] = v
		}
		if len(col.Parameters) > 0 {
			pm := map[string]any{}
			for k, v := range col.Parameters {
				pm[k] = v
			}
			cm["parameters"] = pm
		}
		out = append(out, cm)
	}
	return out
}

// fanoutGlueTables expands a Data Catalog database into its tables.
func fanoutGlueTables(ctx context.Context, c *Clients, parent model.Resource) ([]model.Resource, error) {
	cl := glue.NewFromConfig(c.Cfg(parent.Region))
	db := parent.ID
	p := glue.NewGetTablesPaginator(cl, &glue.GetTablesInput{DatabaseName: &db})
	var kids []model.Resource
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return kids, err
		}
		for _, t := range page.TableList {
			cfg := map[string]any{
				"name":          aws.ToString(t.Name),
				"database_name": db,
			}
			if v := aws.ToString(t.Description); v != "" {
				cfg["description"] = v
			}
			if v := aws.ToString(t.TableType); v != "" {
				cfg["table_type"] = v
			}
			if len(t.Parameters) > 0 {
				m := map[string]any{}
				for k, v := range t.Parameters {
					m[k] = v
				}
				cfg["parameters"] = m
			}
			if cols := glueColumns(t.PartitionKeys); len(cols) > 0 {
				cfg["partition_keys"] = cols
			}
			if sd := t.StorageDescriptor; sd != nil {
				s := map[string]any{}
				if v := aws.ToString(sd.Location); v != "" {
					s["location"] = v
				}
				if v := aws.ToString(sd.InputFormat); v != "" {
					s["input_format"] = v
				}
				if v := aws.ToString(sd.OutputFormat); v != "" {
					s["output_format"] = v
				}
				if cols := glueColumns(sd.Columns); len(cols) > 0 {
					s["columns"] = cols
				}
				if si := sd.SerdeInfo; si != nil {
					sim := map[string]any{}
					if v := aws.ToString(si.Name); v != "" {
						sim["name"] = v
					}
					if v := aws.ToString(si.SerializationLibrary); v != "" {
						sim["serialization_library"] = v
					}
					if len(si.Parameters) > 0 {
						pm := map[string]any{}
						for k, v := range si.Parameters {
							pm[k] = v
						}
						sim["parameters"] = pm
					}
					if len(sim) > 0 {
						s["ser_de_info"] = []any{sim}
					}
				}
				if len(s) > 0 {
					cfg["storage_descriptor"] = s
				}
			}
			kids = append(kids, model.Resource{
				Service: "glue", Type: "table", TFType: "aws_glue_catalog_table",
				Region: parent.Region, Account: parent.Account,
				ID:     parent.Account + ":" + db + ":" + aws.ToString(t.Name),
				Config: cfg,
			})
		}
	}
	return kids, nil
}
